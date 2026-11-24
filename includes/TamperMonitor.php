<?php
/**
 * Tamper detection & immediate security alerts:
 *   - WordGate plugin deactivated (admin UI or WP-CLI)
 *   - WAF loader removed, auto_prepend_file inactive, kill switch added, or stale WAF heartbeat
 *   - New administrator created or user promoted to administrator
 *   - WordGate settings changed / firewall disabled
 *
 * @package WordGate
 */

namespace WordGate;

use WordGate\Firewall\WafInstaller;
use WordGate\Log\EventLog;

final class TamperMonitor {

	const EXPECTED_WAF_OPTION = 'wordgate_expected_waf_mode';

	/** @var bool Prevents duplicate deactivation alerts when both hooks fire. */
	private static $deactivationAlerted = false;

	/** @var array<int,bool> Tracks user IDs already alerted as new admins in this request. */
	private static $alertedAdmins = array();

	public static function register() {
		add_action( 'deactivate_plugin', array( __CLASS__, 'onPluginDeactivate' ), 10, 2 );
		add_action( 'wordgate_hourly', array( __CLASS__, 'checkWafIntegrity' ) );
		add_action( 'user_register', array( __CLASS__, 'onUserRegister' ), 20 );
		add_action( 'set_user_role', array( __CLASS__, 'onRoleChange' ), 20, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'onAddRole' ), 20, 2 );
	}

	/**
	 * Record the WAF protection level that should remain active ("basic" or "extended").
	 */
	public static function setExpectedWafMode( $mode ) {
		if ( '' === $mode || 'none' === $mode ) {
			delete_option( self::EXPECTED_WAF_OPTION );
			return;
		}
		update_option( self::EXPECTED_WAF_OPTION, (string) $mode, false );
	}

	/**
	 * Who triggered the current action (user login + ID, WP-CLI, or anonymous), IP, and UTC time.
	 *
	 * @return array{actor:string,actor_id:int,ip:string,time:string}
	 */
	public static function actorContext() {
		$user_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		$actor   = '';
		if ( $user_id > 0 && function_exists( 'get_userdata' ) ) {
			$u     = get_userdata( $user_id );
			$actor = $u ? $u->user_login . ' (#' . $user_id . ')' : '#' . $user_id;
		} elseif ( defined( 'WP_CLI' ) && WP_CLI ) {
			$actor = 'WP-CLI';
		} else {
			$actor = 'system / unauthenticated';
		}
		$ip = ( defined( 'WP_CLI' ) && WP_CLI ) ? 'cli' : Plugin::clientIp();
		return array(
			'actor'    => $actor,
			'actor_id' => $user_id,
			'ip'       => $ip,
			'time'     => gmdate( 'Y-m-d H:i:s' ) . ' UTC',
		);
	}

	/**
	 * Alert immediately when WordGate is deactivated (works in wp-admin and WP-CLI).
	 */
	public static function onPluginDeactivate( $plugin, $network_deactivating = false ) {
		if ( self::$deactivationAlerted || plugin_basename( WORDGATE_FILE ) !== $plugin ) {
			return;
		}
		self::notifyDeactivation( $network_deactivating ? 'network' : 'site' );
	}

	/**
	 * Fallback called from Installer::deactivate() in case deactivation bypassed deactivate_plugin.
	 */
	public static function notifyDeactivation( $scope = 'site' ) {
		if ( self::$deactivationAlerted ) {
			return;
		}
		self::$deactivationAlerted = true;
		$ctx                       = self::actorContext();
		EventLog::add(
			'tamper_deactivated',
			$ctx['ip'],
			array(
				'user_login' => $ctx['actor'],
				'reason'     => 'WordGate plugin deactivated (' . $scope . ')',
			),
			'critical'
		);
		if ( ! Settings::get( 'notify_tamper' ) ) {
			return;
		}
		Notifications::sendTamper(
			'plugin_deactivated',
			__( 'CRITICAL: WordGate Security was deactivated', 'wordgate' ),
			sprintf(
				/* translators: 1: actor, 2: IP, 3: UTC time */
				__( "The WordGate Security plugin was deactivated on your site.\n\nBy: %1\$s\nIP: %2\$s\nWhen: %3\$s\n\nIf you did not do this, log in immediately, reactivate WordGate, and audit your administrator accounts and files.", 'wordgate' ),
				$ctx['actor'],
				$ctx['ip'],
				$ctx['time']
			)
		);
	}

	/**
	 * Alert when settings are modified (with a higher-severity alert if the firewall is disabled).
	 */
	public static function onSettingsChanged( array $before, array $after ) {
		$changed = self::diffSettings( $before, $after );
		if ( ! $changed ) {
			return;
		}
		$ctx      = self::actorContext();
		$disabled = isset( $after['waf_mode'] ) && 'disabled' === $after['waf_mode'] && ( ! isset( $before['waf_mode'] ) || 'disabled' !== $before['waf_mode'] );

		EventLog::add(
			$disabled ? 'tamper_waf_disabled' : 'settings_changed',
			$ctx['ip'],
			array(
				'user_login' => $ctx['actor'],
				'reason'     => $disabled ? 'Firewall mode set to disabled' : 'Changed: ' . implode( ', ', $changed ),
				'details'    => array( 'keys' => $changed ),
			),
			$disabled ? 'high' : 'info'
		);

		if ( ! Settings::get( 'notify_tamper' ) ) {
			return;
		}

		if ( $disabled ) {
			Notifications::sendTamper(
				'waf_disabled',
				__( 'ALERT: WordGate firewall was disabled', 'wordgate' ),
				sprintf(
					/* translators: 1: actor, 2: IP, 3: UTC time */
					__( "The WordGate web application firewall mode was changed to Disabled.\n\nBy: %1\$s\nIP: %2\$s\nWhen: %3\$s\n\nIf this was not intentional, re-enable the firewall under WordGate → Firewall.", 'wordgate' ),
					$ctx['actor'],
					$ctx['ip'],
					$ctx['time']
				)
			);
			return;
		}

		Notifications::sendTamper(
			'settings_changed',
			__( 'WordGate security settings changed', 'wordgate' ),
			sprintf(
				/* translators: 1: comma-separated keys, 2: actor, 3: IP, 4: UTC time */
				__( "WordGate settings were modified.\n\nChanged: %1\$s\nBy: %2\$s\nIP: %3\$s\nWhen: %4\$s", 'wordgate' ),
				implode( ', ', $changed ),
				$ctx['actor'],
				$ctx['ip'],
				$ctx['time']
			)
		);
	}

	/**
	 * Return setting keys whose values actually changed.
	 *
	 * @return string[]
	 */
	public static function diffSettings( array $before, array $after ) {
		$keys    = array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) );
		$changed = array();
		foreach ( $keys as $k ) {
			$a = array_key_exists( $k, $before ) ? $before[ $k ] : null;
			$b = array_key_exists( $k, $after ) ? $after[ $k ] : null;
			if ( $a !== $b ) {
				$changed[] = (string) $k;
			}
		}
		sort( $changed );
		return $changed;
	}

	/**
	 * Track and alert when a new administrator is registered.
	 */
	public static function onUserRegister( $user_id ) {
		$user = get_userdata( (int) $user_id );
		if ( $user && user_can( $user, 'manage_options' ) ) {
			self::recordAdminCreated( $user, 'registered' );
		}
	}

	/**
	 * Track and alert when an existing user is promoted to an administrator role.
	 */
	public static function onRoleChange( $user_id, $role, $old_roles ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user || ! user_can( $user, 'manage_options' ) ) {
			return;
		}
		// Ignore if they already had an admin-capable role.
		foreach ( (array) $old_roles as $old ) {
			$r = get_role( $old );
			if ( $r && $r->has_cap( 'manage_options' ) ) {
				return;
			}
		}
		self::recordAdminCreated( $user, 'promoted to ' . $role );
	}

	public static function onAddRole( $user_id, $role ) {
		$r    = get_role( $role );
		$user = get_userdata( (int) $user_id );
		if ( $user && $r && $r->has_cap( 'manage_options' ) ) {
			self::recordAdminCreated( $user, 'granted role ' . $role );
		}
	}

	private static function recordAdminCreated( \WP_User $user, $how ) {
		if ( isset( self::$alertedAdmins[ $user->ID ] ) ) {
			return;
		}
		self::$alertedAdmins[ $user->ID ] = true;
		$ctx                              = self::actorContext();

		EventLog::add(
			'admin_created',
			$ctx['ip'],
			array(
				'user_login' => $user->user_login,
				'reason'     => sprintf( 'Administrator %s by %s', $how, $ctx['actor'] ),
				'details'    => array(
					'user_id'  => (int) $user->ID,
					'email'    => (string) $user->user_email,
					'actor'    => $ctx['actor'],
					'actor_id' => $ctx['actor_id'],
					'how'      => $how,
				),
			),
			'high'
		);

		if ( ! Settings::get( 'notify_tamper' ) ) {
			return;
		}
		Notifications::sendTamper(
			'admin_created_' . $user->ID,
			/* translators: %s: username */
			sprintf( __( 'ALERT: New administrator account "%s"', 'wordgate' ), $user->user_login ),
			sprintf(
				/* translators: 1: new admin login, 2: email, 3: how, 4: actor, 5: IP, 6: UTC time */
				__( "A user now has administrator privileges on your site.\n\nAccount: %1\$s (%2\$s)\nAction: %3\$s\nBy: %4\$s\nIP: %5\$s\nWhen: %6\$s\n\nIf you did not authorise this, delete the account immediately and change all administrator passwords.", 'wordgate' ),
				$user->user_login,
				$user->user_email,
				$how,
				$ctx['actor'],
				$ctx['ip'],
				$ctx['time']
			)
		);
	}

	/**
	 * Pure evaluation of WAF loader & heartbeat integrity for hourly checks and unit tests.
	 *
	 * @param string   $expectedMode  'extended' | 'basic' | ''
	 * @param array    $currentStatus Output of WafInstaller::status().
	 * @param string   $wafMode       'enabled' | 'learning' | 'disabled'
	 * @param bool     $killSwitch    Whether disable-waf / WORDGATE_WAF_DISABLE is active.
	 * @param int|null $heartbeatAge  Seconds since last WAF heartbeat, or null if never written.
	 * @param int      $staleSeconds  Age threshold after which a missing/old heartbeat alerts.
	 * @return array[] List of alerts: each has type, reason.
	 */
	public static function evaluateWafHealth( $expectedMode, array $currentStatus, $wafMode, $killSwitch, $heartbeatAge, $staleSeconds = 21600 ) {
		if ( 'disabled' === $wafMode ) {
			return array();
		}
		$alerts  = array();
		$current = isset( $currentStatus['mode'] ) ? (string) $currentStatus['mode'] : 'none';

		if ( $killSwitch ) {
			$alerts[] = array(
				'type'   => 'waf_kill_switch',
				'reason' => 'The WAF emergency kill switch (disable-waf or WORDGATE_WAF_DISABLE) is active.',
			);
		}
		if ( 'extended' === $expectedMode && 'extended' !== $current ) {
			$alerts[] = array(
				'type'   => 'waf_prepend_removed',
				'reason' => sprintf( 'Extended WAF protection (auto_prepend_file) is no longer active (current mode: %s).', $current ),
			);
		} elseif ( 'basic' === $expectedMode && 'none' === $current ) {
			$alerts[] = array(
				'type'   => 'waf_loader_removed',
				'reason' => 'The WordGate must-use WAF loader was removed from mu-plugins.',
			);
		}

		// Heartbeat check: if a loader is installed and WAF isn't kill-switched,
		// a stale heartbeat means the firewall stopped running on web requests.
		if ( ! $killSwitch && 'none' !== $current && null !== $heartbeatAge && $heartbeatAge > $staleSeconds ) {
			$alerts[] = array(
				'type'   => 'waf_heartbeat_stale',
				'reason' => sprintf( 'The WAF has not recorded a heartbeat in %d hours despite being active.', (int) floor( $heartbeatAge / 3600 ) ),
			);
		}

		return $alerts;
	}

	/**
	 * Hourly cron check for WAF tampering / removal / silent failure.
	 */
	public static function checkWafIntegrity() {
		$expected   = (string) get_option( self::EXPECTED_WAF_OPTION, '' );
		$status     = WafInstaller::status();
		$wafMode    = (string) Settings::get( 'waf_mode' );
		$killSwitch = file_exists( WORDGATE_DATA_DIR . '/disable-waf' ) || ( defined( 'WORDGATE_WAF_DISABLE' ) && WORDGATE_WAF_DISABLE );
		$age        = Plugin::storage()->heartbeatAge();

		$alerts = self::evaluateWafHealth( $expected, $status, $wafMode, $killSwitch, $age );
		if ( ! $alerts ) {
			return;
		}
		$ctx = self::actorContext();
		foreach ( $alerts as $a ) {
			EventLog::add(
				'tamper_' . $a['type'],
				$ctx['ip'],
				array(
					'user_login' => $ctx['actor'],
					'reason'     => $a['reason'],
				),
				'critical'
			);
			if ( Settings::get( 'notify_tamper' ) ) {
				Notifications::sendTamper(
					$a['type'],
					__( 'ALERT: WordGate firewall protection changed', 'wordgate' ),
					sprintf(
						/* translators: 1: reason, 2: UTC time */
						__( "WordGate detected a problem with firewall protection:\n\n%1\$s\nDetected: %2\$s\n\nCheck WordGate → Firewall immediately.", 'wordgate' ),
						$a['reason'],
						$ctx['time']
					)
				);
			}
		}
	}
}

<?php
/**
 * Plugin settings (single option) with typed defaults and sanitisation.
 *
 * @package WordGate
 */

namespace WordGate;

final class Settings {

	const OPTION = 'wordgate_settings';

	/** @var array|null */
	private static $cache;

	public static function defaults() {
		return array(
			// Firewall.
			'waf_mode'                   => 'enabled', // enabled | learning | disabled.
			'ip_source'                  => 'REMOTE_ADDR',
			'trusted_proxies'            => '',
			'allowlist_ips'              => '',
			'disabled_rules'             => array(),
			'allow_rules'                => array(),
			'rate_limit_enabled'         => false,
			'rate_limit_rpm'             => 240,
			'rate_limit_action'          => 'throttle',
			'rate_limit_block_minutes'   => 30,
			'not_found_limit'            => 0,
			'block_page_show_reason'     => false,

			// Login security.
			'bf_enabled'                 => true,
			'bf_max_failures'            => 5,
			'bf_window_minutes'          => 15,
			'bf_lockout_minutes'         => 60,
			'bf_invalid_username_lockout' => false,
			'bf_banned_usernames'        => "admin\nadministrator\nroot",
			'generic_login_errors'       => true,
			'tfa_required_roles'         => array(),
			'tfa_grace_days'             => 7,

			// Hardening.
			'xmlrpc'                     => 'on', // on | no_auth | off.
			'block_author_enum'          => true,
			'restrict_rest_users'        => true,
			'hide_wp_version'            => true,
			'disable_file_editor'        => false,
			'security_headers'           => false,

			// Scanner.
			'scan_schedule'              => 'daily', // daily | weekly | off.
			'scan_max_file_kb'           => 2048,
			'scan_uploads'               => true,
			'vuln_check'                 => true,

			// Notifications.
			'notify_email'               => '',
			'notify_scan'                => true,
			'notify_admin_lockout'       => true,
			'notify_admin_login'         => false,

			// Housekeeping.
			'log_retention_days'         => 30,
			'delete_data_on_uninstall'   => false,
		);
	}

	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		}
		return self::$cache;
	}

	public static function get( $key ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : null;
	}

	/**
	 * Newline/comma separated setting as a clean array.
	 *
	 * @return string[]
	 */
	public static function lines( $key ) {
		$raw = (string) self::get( $key );
		return array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) ) );
	}

	/**
	 * Merge, sanitise, persist and propagate to the WAF config file.
	 */
	public static function update( array $changes ) {
		$all = array_merge( self::all(), self::sanitize( $changes ) );
		update_option( self::OPTION, $all, true );
		self::$cache = $all;
		Firewall\WafConfig::sync();
		return $all;
	}

	public static function sanitize( array $in ) {
		$defaults = self::defaults();
		$out      = array();
		foreach ( $in as $key => $value ) {
			if ( ! array_key_exists( $key, $defaults ) ) {
				continue;
			}
			$default = $defaults[ $key ];
			if ( is_bool( $default ) ) {
				$out[ $key ] = (bool) $value;
			} elseif ( is_int( $default ) ) {
				$out[ $key ] = max( 0, (int) $value );
			} elseif ( is_array( $default ) ) {
				$out[ $key ] = is_array( $value ) ? $value : array();
			} else {
				$out[ $key ] = sanitize_textarea_field( (string) $value );
			}
		}

		$enums = array(
			'waf_mode'          => array( 'enabled', 'learning', 'disabled' ),
			'rate_limit_action' => array( 'throttle', 'block' ),
			'xmlrpc'            => array( 'on', 'no_auth', 'off' ),
			'scan_schedule'     => array( 'daily', 'weekly', 'off' ),
			'ip_source'         => array( 'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP' ),
		);
		foreach ( $enums as $key => $allowed ) {
			if ( isset( $out[ $key ] ) && ! in_array( $out[ $key ], $allowed, true ) ) {
				$out[ $key ] = $defaults[ $key ];
			}
		}

		foreach ( array( 'trusted_proxies', 'allowlist_ips' ) as $key ) {
			if ( isset( $out[ $key ] ) ) {
				$valid       = array_filter(
					array_map( 'trim', preg_split( '/[\r\n,]+/', $out[ $key ] ) ),
					array( Waf\IpUtil::class, 'isValidRange' )
				);
				$out[ $key ] = implode( "\n", $valid );
			}
		}
		if ( isset( $out['disabled_rules'] ) ) {
			$out['disabled_rules'] = array_values( array_unique( array_map( 'intval', $out['disabled_rules'] ) ) );
		}
		if ( isset( $out['tfa_required_roles'] ) ) {
			$out['tfa_required_roles'] = array_values( array_map( 'sanitize_key', $out['tfa_required_roles'] ) );
		}
		if ( isset( $out['notify_email'] ) ) {
			$out['notify_email'] = sanitize_email( $out['notify_email'] );
		}
		if ( isset( $out['bf_max_failures'] ) ) {
			$out['bf_max_failures'] = max( 1, $out['bf_max_failures'] );
		}
		return $out;
	}

	public static function flush() {
		self::$cache = null;
	}
}

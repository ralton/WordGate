<?php
/**
 * Email alerts, rate limited so an attack cannot flood the inbox.
 *
 * @package WordGate
 */

namespace WordGate;

final class Notifications {

	public static function register() {
		if ( Settings::get( 'notify_admin_login' ) ) {
			add_action( 'wp_login', array( __CLASS__, 'adminLogin' ), 20, 2 );
		}
	}

	public static function recipient() {
		$email = (string) Settings::get( 'notify_email' );
		return is_email( $email ) ? $email : get_option( 'admin_email' );
	}

	/**
	 * @param string $key Throttle key; at most one mail per key per $throttle seconds.
	 */
	public static function send( $key, $subject, $body, $throttle = 600 ) {
		$tkey = 'wordgate_mail_' . md5( $key );
		if ( $throttle > 0 && get_transient( $tkey ) ) {
			return false;
		}
		if ( $throttle > 0 ) {
			set_transient( $tkey, 1, $throttle );
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body .= "\n\n--\n" . sprintf(
			/* translators: 1: site URL, 2: settings URL */
			__( "Sent by WordGate on %1\$s\nChange notification settings: %2\$s", 'wordgate' ),
			home_url(),
			admin_url( 'admin.php?page=wordgate-settings' )
		);
		return wp_mail( self::recipient(), '[' . $site . '] ' . $subject, $body );
	}

	/**
	 * Send a tamper alert: always bypasses throttling for the first event of each
	 * type per UTC day, then applies a short cooldown for repeated identical events.
	 */
	public static function sendTamper( $type, $subject, $body ) {
		$dayKey = 'wordgate_tamper_' . md5( $type . '_' . gmdate( 'Y-m-d' ) );
		if ( ! get_transient( $dayKey ) ) {
			set_transient( $dayKey, 1, DAY_IN_SECONDS );
			return self::send( 'tamper_' . $type, $subject, $body, 0 );
		}
		return self::send( 'tamper_' . $type, $subject, $body, 600 );
	}

	public static function adminLockout( \WP_User $user, $ip, $reason ) {
		if ( ! Settings::get( 'notify_admin_lockout' ) ) {
			return;
		}
		self::send(
			'lockout_' . $ip,
			__( 'Administrator login locked out', 'wordgate' ),
			sprintf(
				/* translators: 1: username, 2: IP, 3: reason */
				__( "An IP address was locked out after trying to log in as the administrator \"%1\$s\".\n\nIP: %2\$s\nReason: %3\$s\n\nIf this was you, wait for the lockout to expire or unblock the IP under WordGate → Blocking.", 'wordgate' ),
				$user->user_login,
				$ip,
				$reason
			)
		);
	}

	public static function adminLogin( $user_login, $user ) {
		if ( ! ( $user instanceof \WP_User ) || ! user_can( $user, 'manage_options' ) ) {
			return;
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		self::send(
			'login_' . $user->ID . '_' . Plugin::clientIp(),
			__( 'Administrator logged in', 'wordgate' ),
			sprintf(
				/* translators: 1: username, 2: IP, 3: user agent */
				__( "The administrator \"%1\$s\" just logged in.\n\nIP: %2\$s\nBrowser: %3\$s\n\nIf this wasn't you, change your password immediately and enable two-factor authentication.", 'wordgate' ),
				$user->user_login,
				Plugin::clientIp(),
				$ua
			),
			3600
		);
	}

	/**
	 * @param array $summary From ScanRunner.
	 */
	public static function scanComplete( array $summary ) {
		if ( ! Settings::get( 'notify_scan' ) || empty( $summary['new_issues'] ) ) {
			return;
		}
		$lines = array();
		foreach ( array_slice( $summary['new_issue_titles'], 0, 20 ) as $t ) {
			$lines[] = '• ' . $t;
		}
		self::send(
			'scan_' . md5( implode( '|', $summary['new_issue_titles'] ) ),
			/* translators: %d: number of new issues */
			sprintf( _n( 'Security scan found %d new issue', 'Security scan found %d new issues', $summary['new_issues'], 'wordgate' ), $summary['new_issues'] ),
			implode( "\n", $lines ) . "\n\n" . sprintf(
				/* translators: %s: URL */
				__( 'Review the results: %s', 'wordgate' ),
				admin_url( 'admin.php?page=wordgate-scan' )
			),
			0
		);
	}
}

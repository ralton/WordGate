<?php
/**
 * Issues the signed "wordgate_admin" cookie that lets the pre-WordPress WAF
 * recognise trusted users and skip rules marked admin_bypass (e.g. HTML or
 * script in post content).
 *
 * Only users with unfiltered_html get it: they are already allowed by
 * WordPress to publish arbitrary HTML/JS, so the bypass grants nothing new.
 *
 * @package WordGate
 */

namespace WordGate\Login;

use WordGate\Firewall\WafConfig;
use WordGate\Waf\Engine;

final class AdminCookie {

	const NAME = 'wordgate_admin';

	public static function register() {
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'onLogin' ), 10, 6 );
		add_action( 'clear_auth_cookie', array( __CLASS__, 'clear' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure' ) );
	}

	public static function onLogin( $cookie, $expire, $expiration, $user_id ) {
		if ( user_can( $user_id, 'unfiltered_html' ) ) {
			self::set( $user_id, $expiration, $expire );
		}
	}

	/**
	 * Issue the cookie for already-logged-in admins (e.g. right after install).
	 */
	public static function ensure() {
		if ( isset( $_COOKIE[ self::NAME ] ) || ! current_user_can( 'unfiltered_html' ) || headers_sent() ) {
			return;
		}
		self::set( get_current_user_id(), time() + 2 * DAY_IN_SECONDS, 0 );
	}

	private static function set( $user_id, $expiration, $expire ) {
		if ( headers_sent() ) {
			return;
		}
		$token = Engine::makeAdminToken( $user_id, $expiration, WafConfig::secret() );
		setcookie( self::NAME, $token, (int) $expire, '/', COOKIE_DOMAIN, is_ssl(), true ); // phpcs:ignore
		$_COOKIE[ self::NAME ] = $token;
	}

	public static function clear() {
		if ( ! headers_sent() ) {
			setcookie( self::NAME, ' ', time() - YEAR_IN_SECONDS, '/', COOKIE_DOMAIN ); // phpcs:ignore
		}
		unset( $_COOKIE[ self::NAME ] );
	}
}

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

	/** Short lifetime so a captured bypass cookie expires quickly; refreshed in admin_init. */
	const TTL = 14400; // 4 hours.

	/** Refresh when fewer than this many seconds remain. */
	const REFRESH_BEFORE = 3600;

	public static function register() {
		add_action( 'set_logged_in_cookie', array( __CLASS__, 'onLogin' ), 10, 6 );
		add_action( 'clear_auth_cookie', array( __CLASS__, 'clear' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure' ) );
		add_action( 'set_user_role', array( __CLASS__, 'onRoleChange' ), 10, 3 );
		add_action( 'after_password_reset', array( __CLASS__, 'onPasswordReset' ) );
	}

	public static function onLogin( $cookie, $expire, $expiration, $user_id ) {
		if ( TwoFactor::isIntercepting( $user_id ) ) {
			return;
		}
		if ( user_can( $user_id, 'unfiltered_html' ) ) {
			$token_exp  = min( (int) $expiration, time() + self::TTL );
			$cookie_exp = $expire > 0 ? min( (int) $expire, $token_exp ) : 0;
			self::set( $user_id, $token_exp, $cookie_exp );
		}
	}

	/**
	 * Issue or refresh the cookie for logged-in admins (e.g. right after install
	 * or as the short TTL approaches expiry).
	 */
	public static function ensure() {
		if ( ! current_user_can( 'unfiltered_html' ) || headers_sent() ) {
			return;
		}
		if ( isset( $_COOKIE[ self::NAME ] ) && is_string( $_COOKIE[ self::NAME ] ) ) {
			$token = sanitize_text_field( wp_unslash( $_COOKIE[ self::NAME ] ) );
			if ( Engine::verifyAdminToken( $token, WafConfig::secret() ) ) {
				$parts = explode( '|', $token );
				if ( (int) $parts[1] - time() > self::REFRESH_BEFORE ) {
					return;
				}
			}
		}
		self::set( get_current_user_id(), time() + self::TTL, 0 );
	}

	/**
	 * Rotate the signing secret when a user is demoted (so a captured cookie from
	 * a former admin can no longer bypass WAF rules).
	 */
	public static function onRoleChange( $user_id, $role, $old_roles ) {
		if ( ! user_can( $user_id, 'unfiltered_html' ) && ! empty( $old_roles ) ) {
			WafConfig::rotateSecret();
		}
	}

	public static function onPasswordReset( $user ) {
		if ( $user instanceof \WP_User && user_can( $user, 'unfiltered_html' ) ) {
			WafConfig::rotateSecret();
		}
	}

	private static function set( $user_id, $expiration, $expire ) {
		if ( headers_sent() ) {
			return;
		}
		$token = Engine::makeAdminToken( $user_id, $expiration, WafConfig::secret() );
		setcookie(
			self::NAME,
			$token,
			array(
				'expires'  => (int) $expire,
				'path'     => '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ self::NAME ] = $token;
	}

	public static function clear() {
		if ( ! headers_sent() ) {
			setcookie(
				self::NAME,
				'',
				array(
					'expires'  => time() - YEAR_IN_SECONDS,
					'path'     => '/',
					'domain'   => COOKIE_DOMAIN,
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
		unset( $_COOKIE[ self::NAME ] );
	}
}

<?php
/**
 * Brute-force protection: per-IP failure counting with temporary lockouts.
 *
 * Lockouts are written to the shared block list with scope "login", so the WAF
 * rejects further attempts before WordPress even loads.
 *
 * Lockouts are by IP only. Locking out a *username* would let an attacker lock
 * the real administrator out of their own site.
 *
 * @package WordGate
 */

namespace WordGate\Login;

use WordGate\Log\EventLog;
use WordGate\Notifications;
use WordGate\Plugin;
use WordGate\Settings;
use WordGate\Waf\IpUtil;

final class BruteForce {

	public static function register() {
		if ( Settings::get( 'bf_enabled' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'rejectIfLocked' ), 1, 3 );
			add_action( 'wp_login_failed', array( __CLASS__, 'onFailure' ), 10, 2 );
			add_action( 'wp_login', array( __CLASS__, 'onSuccess' ), 10, 2 );
		}
		if ( Settings::get( 'generic_login_errors' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'genericErrors' ), 99, 3 );
		}
	}

	private static function isAllowlisted( $ip ) {
		return IpUtil::matchesAny( $ip, Settings::lines( 'allowlist_ips' ) );
	}

	/**
	 * @param \WP_User|\WP_Error|null $user
	 */
	public static function rejectIfLocked( $user, $username = '', $password = '' ) {
		$ip = Plugin::clientIp();
		if ( self::isAllowlisted( $ip ) ) {
			return $user;
		}
		$block = Plugin::storage()->findBlock( $ip, true );
		if ( $block ) {
			remove_action( 'wp_login_failed', array( __CLASS__, 'onFailure' ), 10 );
			return new \WP_Error( 'wordgate_locked_out', self::lockedMessage( $block ) );
		}

		// Attempts on well-known usernames that do not exist on this site are
		// a reliable bot signal: lock out immediately.
		if ( '' !== $username && '' !== $password ) {
			$banned = array_map( 'strtolower', Settings::lines( 'bf_banned_usernames' ) );
			if ( in_array( strtolower( $username ), $banned, true ) && ! username_exists( $username ) && ! email_exists( $username ) ) {
				self::lockout( $ip, $username, __( 'Attempted login with a banned username', 'wordgate' ) );
				remove_action( 'wp_login_failed', array( __CLASS__, 'onFailure' ), 10 );
				return new \WP_Error( 'wordgate_locked_out', self::lockedMessage( Plugin::storage()->findBlock( $ip, true ) ) );
			}
		}
		return $user;
	}

	public static function onFailure( $username, $error = null ) {
		$ip = Plugin::clientIp();
		EventLog::add(
			'login_failed',
			$ip,
			array(
				'user_login' => $username,
				'uri'        => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
				'reason'     => is_wp_error( $error ) ? $error->get_error_code() : '',
			),
			'low'
		);
		if ( self::isAllowlisted( $ip ) ) {
			return;
		}

		$invalid_user = ! username_exists( $username ) && ! email_exists( $username );
		if ( $invalid_user && Settings::get( 'bf_invalid_username_lockout' ) ) {
			self::lockout( $ip, $username, __( 'Login attempt with a non-existent username', 'wordgate' ) );
			return;
		}

		$window = max( 1, (int) Settings::get( 'bf_window_minutes' ) ) * MINUTE_IN_SECONDS;
		$count  = Plugin::storage()->increment( 'login:' . $ip, $window );
		if ( $count >= (int) Settings::get( 'bf_max_failures' ) ) {
			/* translators: %d: number of failed attempts */
			self::lockout( $ip, $username, sprintf( __( '%d failed login attempts', 'wordgate' ), $count ) );
		}
	}

	public static function onSuccess( $user_login, $user ) {
		Plugin::storage()->resetCounter( 'login:' . Plugin::clientIp() );
	}

	public static function lockout( $ip, $username, $reason ) {
		$minutes = max( 1, (int) Settings::get( 'bf_lockout_minutes' ) );
		Plugin::storage()->addBlock( $ip, $reason, $minutes, 'login', 'brute_force' );
		Plugin::storage()->resetCounter( 'login:' . $ip );
		EventLog::add(
			'lockout',
			$ip,
			array(
				'user_login' => $username,
				'reason'     => $reason,
				'details'    => array( 'minutes' => $minutes ),
			),
			'medium'
		);

		$user = get_user_by( 'login', $username );
		if ( ! $user ) {
			$user = get_user_by( 'email', $username );
		}
		if ( $user && user_can( $user, 'manage_options' ) ) {
			Notifications::adminLockout( $user, $ip, $reason );
		}
	}

	private static function lockedMessage( $block ) {
		$minutes = $block && ! empty( $block['expires'] ) ? max( 1, (int) ceil( ( $block['expires'] - time() ) / 60 ) ) : 0;
		return $minutes
			/* translators: %d: minutes until the lockout ends */
			? sprintf( _n( 'Too many failed login attempts from your IP address. Try again in %d minute.', 'Too many failed login attempts from your IP address. Try again in %d minutes.', $minutes, 'wordgate' ), $minutes )
			: __( 'Login from your IP address has been blocked.', 'wordgate' );
	}

	/**
	 * Don't reveal whether the username or the password was wrong.
	 */
	public static function genericErrors( $user, $username = '', $password = '' ) {
		if ( is_wp_error( $user ) && array_intersect( $user->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return new \WP_Error(
				'wordgate_invalid_credentials',
				sprintf(
					'<strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a>',
					esc_html__( 'Error:', 'wordgate' ),
					esc_html__( 'The username or password you entered is incorrect.', 'wordgate' ),
					esc_url( wp_lostpassword_url() ),
					esc_html__( 'Lost your password?', 'wordgate' )
				)
			);
		}
		return $user;
	}
}

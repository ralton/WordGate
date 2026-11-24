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
use WordGate\Waf\Storage;

final class BruteForce {

	public static function register() {
		if ( Settings::get( 'bf_enabled' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'rejectIfLocked' ), 1, 3 );
			add_action( 'wp_login_failed', array( __CLASS__, 'onFailure' ), 10, 2 );
			add_action( 'wp_login', array( __CLASS__, 'onSuccess' ), 10, 2 );
			// Application passwords (REST API / XML-RPC basic auth) are validated by
			// wp_authenticate_application_password(), outside the authenticate filter
			// chain, so they need their own hooks.
			add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'rejectAppPasswordIfLocked' ), 10, 4 );
			add_action( 'application_password_failed_authentication', array( __CLASS__, 'onAppPasswordFailure' ) );
		}
		if ( Settings::get( 'generic_login_errors' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'genericErrors' ), 99, 3 );
			add_filter( 'rest_authentication_errors', array( __CLASS__, 'genericRestErrors' ), 95 );
		}
		if ( (int) Settings::get( 'bf_max_password_resets' ) > 0 || Settings::get( 'generic_login_errors' ) ) {
			add_action( 'lostpassword_post', array( __CLASS__, 'onLostPasswordPost' ), 10, 2 );
		}
	}

	/**
	 * Pure rate-limit evaluation for password reset requests (per IP and per target user).
	 *
	 * @return array{status:string,ip_count:int,user_count:int}
	 */
	public static function checkLostPasswordRate( Storage $storage, $ip, $user_id, $limit, $allowlisted = false, $window = 3600 ) {
		$limit = (int) $limit;
		if ( $limit <= 0 ) {
			return array(
				'status'     => 'allow',
				'ip_count'   => 0,
				'user_count' => 0,
			);
		}

		$ip_count = 0;
		if ( ! $allowlisted ) {
			$ip_count = $storage->increment( 'lostpw_ip:' . $ip, $window );
			if ( $ip_count > $limit ) {
				return array(
					'status'     => 'ip_limit',
					'ip_count'   => $ip_count,
					'user_count' => 0,
				);
			}
		}

		$user_count = 0;
		$user_id    = (int) $user_id;
		if ( $user_id > 0 ) {
			$user_count = $storage->increment( 'lostpw_user:' . $user_id, $window );
			if ( $user_count > $limit ) {
				return array(
					'status'     => 'user_limit',
					'ip_count'   => $ip_count,
					'user_count' => $user_count,
				);
			}
		}

		return array(
			'status'     => 'allow',
			'ip_count'   => $ip_count,
			'user_count' => $user_count,
		);
	}

	/**
	 * Rate-limit wp-login.php?action=lostpassword per IP and per user, and mask
	 * whether an account exists so reset requests cannot be used to probe emails.
	 *
	 * @param \WP_Error       $errors
	 * @param \WP_User|false  $user_data
	 */
	public static function onLostPasswordPost( $errors, $user_data = false ) {
		if ( ! ( $errors instanceof \WP_Error ) ) {
			return;
		}
		if ( in_array( 'empty_username', $errors->get_error_codes(), true ) ) {
			return;
		}

		$ip          = Plugin::clientIp();
		$allowlisted = self::isAllowlisted( $ip );
		// phpcs:ignore WordPress.Security.NonceVerification
		$raw_login   = isset( $_POST['user_login'] ) ? sanitize_text_field( wp_unslash( $_POST['user_login'] ) ) : '';
		$login       = $user_data instanceof \WP_User ? $user_data->user_login : $raw_login;

		if ( ! $allowlisted ) {
			$block = Plugin::storage()->findBlock( $ip, true );
			if ( $block ) {
				$errors->add( 'wordgate_locked_out', self::lockedMessage( $block ) );
				return;
			}
		}

		$limit = (int) Settings::get( 'bf_max_password_resets' );
		if ( $limit > 0 ) {
			$decision = self::checkLostPasswordRate(
				Plugin::storage(),
				$ip,
				$user_data instanceof \WP_User ? $user_data->ID : 0,
				$limit,
				$allowlisted,
				HOUR_IN_SECONDS
			);
			if ( 'ip_limit' === $decision['status'] ) {
				/* translators: %d: number of password reset requests */
				self::lockout( $ip, $login, sprintf( __( '%d password reset requests in an hour', 'wordgate' ), $decision['ip_count'] ) );
				Plugin::storage()->resetCounter( 'lostpw_ip:' . $ip );
				$errors->add( 'wordgate_locked_out', self::lockedMessage( Plugin::storage()->findBlock( $ip, true ) ) );
				return;
			}
			if ( 'user_limit' === $decision['status'] ) {
				EventLog::add(
					'lostpassword_throttled',
					$ip,
					array(
						'user_login' => $login,
						'reason'     => sprintf( 'Exceeded %d password reset requests per hour for user', $limit ),
					),
					'medium'
				);
				if ( self::isWebLostPasswordForm() ) {
					self::redirectLostPasswordGeneric();
				}
				$errors->add( 'wordgate_lostpassword_throttled', __( 'Too many password reset requests. Please try again later.', 'wordgate' ) );
				return;
			}
		}

		// Show the exact same confirmation screen for unknown accounts as for real ones.
		$codes         = $errors->get_error_codes();
		$unknown_codes = array( 'invalidcombo', 'invalid_email', 'invalid_username' );
		if ( $codes && ! array_diff( $codes, $unknown_codes ) && self::isWebLostPasswordForm() ) {
			EventLog::add(
				'lostpassword_unknown',
				$ip,
				array(
					'user_login' => $raw_login,
					'reason'     => 'Password reset requested for unknown account',
				),
				'low'
			);
			self::redirectLostPasswordGeneric();
		}
	}

	private static function isWebLostPasswordForm() {
		// phpcs:ignore WordPress.Security.NonceVerification
		return ! wp_doing_ajax() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && isset( $_POST['user_login'] );
	}

	private static function redirectLostPasswordGeneric() {
		// phpcs:ignore WordPress.Security.NonceVerification
		$redirect = ! empty( $_REQUEST['redirect_to'] )
			? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) )
			: add_query_arg( 'checkemail', 'confirm', wp_login_url() );
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Refuse application-password logins from locked-out IPs, even with the right password.
	 *
	 * @param \WP_Error $error
	 */
	public static function rejectAppPasswordIfLocked( $error, $user = null, $item = null, $password = '' ) {
		$ip = Plugin::clientIp();
		if ( self::isAllowlisted( $ip ) ) {
			return;
		}
		$block = Plugin::storage()->findBlock( $ip, true );
		if ( $block ) {
			$error->add( 'wordgate_locked_out', self::lockedMessage( $block ), array( 'status' => 403 ) );
		}
	}

	/**
	 * Count failed application-password logins toward the per-IP lockout.
	 *
	 * @param \WP_Error $error
	 */
	public static function onAppPasswordFailure( $error ) {
		if ( is_wp_error( $error ) && in_array( 'wordgate_locked_out', $error->get_error_codes(), true ) ) {
			return; // Already locked out; don't extend or double-log.
		}
		$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_user( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : '';
		self::onFailure( $username, $error );
	}

	/**
	 * The REST API reports "invalid_username" vs "incorrect_password" for
	 * application passwords, which reveals whether an account exists.
	 *
	 * @param \WP_Error|null|true $result
	 */
	public static function genericRestErrors( $result ) {
		if ( is_wp_error( $result ) && array_intersect( $result->get_error_codes(), array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return new \WP_Error( 'wordgate_invalid_credentials', __( 'Invalid username or application password.', 'wordgate' ), array( 'status' => 401 ) );
		}
		return $result;
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

	public static function lockedMessage( $block ) {
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

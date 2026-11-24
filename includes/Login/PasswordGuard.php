<?php
/**
 * Breached & common password protection using a bundled common-password list
 * plus Have I Been Pwned's k-anonymity range API.
 *
 * Privacy: only the first 5 hex characters of the SHA-1 hash leave the site,
 * with `Add-Padding: true` enabled. Full hashes and plaintext passwords are
 * never transmitted. Fails open if the HIBP API is unreachable.
 *
 * @package WordGate
 */

namespace WordGate\Login;

use WordGate\Log\EventLog;
use WordGate\Plugin;
use WordGate\Settings;

final class PasswordGuard {

	const HIBP_API         = 'https://api.pwnedpasswords.com/range/';
	const FORCE_RESET_META = 'wordgate_pw_force_reset';
	const WARN_META        = 'wordgate_pw_breached_warn';

	/** @var array<string,bool>|null Memoised lowercase common passwords map. */
	private static $commonMap;

	public static function register() {
		if ( ! Settings::get( 'pw_guard_enabled' ) ) {
			return;
		}
		add_filter( 'authenticate', array( __CLASS__, 'checkOnLogin' ), 50, 3 );
		add_action( 'user_profile_update_errors', array( __CLASS__, 'checkProfileUpdate' ), 10, 3 );
		add_action( 'validate_password_reset', array( __CLASS__, 'checkPasswordReset' ), 10, 2 );
		add_filter( 'registration_errors', array( __CLASS__, 'checkRegistration' ), 10, 3 );
		add_action( 'profile_update', array( __CLASS__, 'clearFlagsOnPasswordChange' ), 10, 2 );
		add_action( 'after_password_reset', array( __CLASS__, 'clearFlagsOnReset' ) );

		// WooCommerce account & registration forms (no-op when WooCommerce is inactive).
		add_action( 'woocommerce_save_account_details_errors', array( __CLASS__, 'checkWooAccountSave' ), 10, 2 );
		add_filter( 'woocommerce_registration_errors', array( __CLASS__, 'checkWooRegistration' ), 10, 3 );

		add_action( 'admin_notices', array( __CLASS__, 'adminNotices' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforcePasswordReset' ), 2 );
	}

	/* ---------------------------------------------------------------------
	 * Pure check helpers (no WordPress dependency; directly unit-testable)
	 * ------------------------------------------------------------------- */

	/**
	 * Is the password in the bundled common-passwords list (case-insensitive)?
	 */
	public static function isCommon( $password ) {
		if ( null === self::$commonMap ) {
			self::$commonMap = array();
			$file            = __DIR__ . '/common-passwords.txt';
			if ( is_readable( $file ) ) {
				foreach ( file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $line ) {
					$line = strtolower( trim( $line ) );
					if ( '' !== $line && '#' !== $line[0] ) {
						self::$commonMap[ $line ] = true;
					}
				}
			}
		}
		return isset( self::$commonMap[ strtolower( (string) $password ) ] );
	}

	/**
	 * Parse a HIBP range API body for a 35-char uppercase SHA-1 suffix.
	 * Ignores padded entries (count 0) returned when Add-Padding: true is set.
	 *
	 * @return int Breach occurrence count (0 = not found).
	 */
	public static function parseHibpRange( $body, $suffix ) {
		$suffix = strtoupper( (string) $suffix );
		foreach ( preg_split( '/\r\n|\r|\n/', (string) $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || false === strpos( $line, ':' ) ) {
				continue;
			}
			list( $hashSuffix, $count ) = explode( ':', $line, 2 );
			if ( hash_equals( $suffix, strtoupper( trim( $hashSuffix ) ) ) ) {
				$n = (int) trim( $count );
				return $n > 0 ? $n : 0;
			}
		}
		return 0;
	}

	/**
	 * Query Have I Been Pwned using k-anonymity (5-char SHA-1 prefix only).
	 *
	 * @param callable|null $httpGet Optional fn(string $url, array $headers): ?string for testing.
	 * @return int|null Breach count (0 = clean), or null on network error (fail open).
	 */
	public static function checkHibp( $password, ?callable $httpGet = null ) {
		$sha1   = strtoupper( sha1( (string) $password ) );
		$prefix = substr( $sha1, 0, 5 );
		$suffix = substr( $sha1, 5 );
		$url    = self::HIBP_API . $prefix;
		$headers = array(
			'Add-Padding' => 'true',
			'User-Agent'  => 'WordGate-WordPress-Security',
		);

		$body = null;
		if ( null !== $httpGet ) {
			$body = $httpGet( $url, $headers );
		} elseif ( function_exists( 'wp_remote_get' ) ) {
			$cacheKey = 'wordgate_hibp_' . $prefix;
			$cached   = get_site_transient( $cacheKey );
			if ( is_string( $cached ) ) {
				$body = $cached;
			} else {
				$res = wp_remote_get(
					$url,
					array(
						'timeout' => 5,
						'headers' => $headers,
					)
				);
				if ( ! is_wp_error( $res ) && 200 === wp_remote_retrieve_response_code( $res ) ) {
					$body = (string) wp_remote_retrieve_body( $res );
					set_site_transient( $cacheKey, $body, 15 * MINUTE_IN_SECONDS );
				}
			}
		}

		if ( ! is_string( $body ) || '' === $body ) {
			return null; // Fail open.
		}
		return self::parseHibpRange( $body, $suffix );
	}

	/**
	 * Evaluate a password against the local common list and optionally HIBP.
	 *
	 * @return array{compromised:bool,source:string,count:int}
	 */
	public static function evaluate( $password, $useRemote = true, ?callable $httpGet = null ) {
		if ( '' === (string) $password ) {
			return array( 'compromised' => false, 'source' => 'clean', 'count' => 0 );
		}
		if ( self::isCommon( $password ) ) {
			return array( 'compromised' => true, 'source' => 'common', 'count' => 1 );
		}
		if ( $useRemote ) {
			$count = self::checkHibp( $password, $httpGet );
			if ( null !== $count && $count > 0 ) {
				return array( 'compromised' => true, 'source' => 'hibp', 'count' => $count );
			}
		}
		return array( 'compromised' => false, 'source' => 'clean', 'count' => 0 );
	}

	/**
	 * Should a compromised password be blocked / forced to reset for these roles?
	 *
	 * @param string[] $userRoles
	 * @param string[] $enforcedRoles
	 */
	public static function shouldEnforce( array $userRoles, array $enforcedRoles ) {
		return (bool) array_intersect( $userRoles, $enforcedRoles );
	}

	/* ---------------------------------------------------------------------
	 * WordPress & WooCommerce integration
	 * ------------------------------------------------------------------- */

	private static function checkPassword( $password ) {
		return self::evaluate( $password, (bool) Settings::get( 'pw_hibp_enabled' ) );
	}

	private static function isEnforcedForRoles( array $roles ) {
		return self::shouldEnforce( $roles, (array) Settings::get( 'pw_enforce_roles' ) );
	}

	private static function messageForResult( array $result ) {
		if ( 'common' === $result['source'] ) {
			return __( 'This password is on a list of very common passwords and can be guessed immediately. Please choose a stronger, unique password.', 'wordgate' );
		}
		/* translators: %s: formatted breach count */
		return sprintf(
			__( 'This password has appeared in %s known data breaches (Have I Been Pwned). Please choose a unique password you have not used elsewhere.', 'wordgate' ),
			number_format_i18n( $result['count'] )
		);
	}

	/**
	 * Check password strength/breach status on successful interactive login.
	 *
	 * @param \WP_User|\WP_Error|null $user
	 */
	public static function checkOnLogin( $user, $username = '', $password = '' ) {
		if ( ! ( $user instanceof \WP_User ) || '' === (string) $password ) {
			return $user;
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return $user;
		}
		$res = self::checkPassword( $password );
		if ( ! $res['compromised'] ) {
			delete_user_meta( $user->ID, self::FORCE_RESET_META );
			delete_user_meta( $user->ID, self::WARN_META );
			return $user;
		}

		EventLog::add(
			'breached_password_login',
			Plugin::clientIp(),
			array(
				'user_login' => $user->user_login,
				'reason'     => 'common' === $res['source'] ? 'Logged in with common password' : sprintf( 'Logged in with breached password (%d hits)', $res['count'] ),
			),
			self::isEnforcedForRoles( (array) $user->roles ) ? 'high' : 'medium'
		);

		if ( self::isEnforcedForRoles( (array) $user->roles ) ) {
			update_user_meta( $user->ID, self::FORCE_RESET_META, $res['source'] );
		} else {
			update_user_meta( $user->ID, self::WARN_META, $res['source'] );
		}
		return $user;
	}

	/**
	 * Block or warn when a user updates their password in wp-admin / profile.php.
	 *
	 * @param \WP_Error $errors
	 * @param bool      $update
	 * @param object    $user
	 */
	public static function checkProfileUpdate( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) {
			return;
		}
		$roles = array();
		if ( ! empty( $user->role ) ) {
			$roles[] = (string) $user->role;
		} elseif ( ! empty( $user->ID ) ) {
			$existing = get_userdata( (int) $user->ID );
			if ( $existing ) {
				$roles = (array) $existing->roles;
			}
		}
		$res = self::checkPassword( (string) $user->user_pass );
		if ( ! $res['compromised'] ) {
			return;
		}
		if ( self::isEnforcedForRoles( $roles ) ) {
			$errors->add( 'wordgate_breached_password', '<strong>' . esc_html__( 'Error:', 'wordgate' ) . '</strong> ' . esc_html( self::messageForResult( $res ) ) );
		} elseif ( ! empty( $user->ID ) ) {
			update_user_meta( (int) $user->ID, self::WARN_META, $res['source'] );
		}
	}

	/**
	 * Block or warn on wp-login.php?action=rp password reset.
	 *
	 * @param \WP_Error $errors
	 * @param \WP_User  $user
	 */
	public static function checkPasswordReset( $errors, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$pass = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		if ( '' === $pass || ! ( $user instanceof \WP_User ) ) {
			return;
		}
		$res = self::checkPassword( $pass );
		if ( ! $res['compromised'] ) {
			return;
		}
		if ( self::isEnforcedForRoles( (array) $user->roles ) ) {
			$errors->add( 'wordgate_breached_password', self::messageForResult( $res ) );
		} else {
			update_user_meta( $user->ID, self::WARN_META, $res['source'] );
		}
	}

	/**
	 * Block compromised passwords on registration forms that supply a password.
	 *
	 * @param \WP_Error $errors
	 */
	public static function checkRegistration( $errors, $sanitized_user_login = '', $user_email = '' ) {
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$pass = '';
		if ( isset( $_POST['user_pass'] ) ) {
			$pass = (string) wp_unslash( $_POST['user_pass'] );
		} elseif ( isset( $_POST['pass1'] ) ) {
			$pass = (string) wp_unslash( $_POST['pass1'] );
		}
		// phpcs:enable
		if ( '' === $pass ) {
			return $errors;
		}
		$res = self::checkPassword( $pass );
		if ( $res['compromised'] && self::isEnforcedForRoles( array( (string) get_option( 'default_role', 'subscriber' ) ) ) ) {
			$errors->add( 'wordgate_breached_password', self::messageForResult( $res ) );
		}
		return $errors;
	}

	/**
	 * WooCommerce My Account → Account Details password change.
	 *
	 * @param \WP_Error $errors
	 * @param object    $user
	 */
	public static function checkWooAccountSave( $errors, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$pass = isset( $_POST['password_1'] ) ? (string) wp_unslash( $_POST['password_1'] ) : '';
		if ( '' === $pass ) {
			return;
		}
		$res = self::checkPassword( $pass );
		if ( ! $res['compromised'] ) {
			if ( ! empty( $user->ID ) ) {
				delete_user_meta( (int) $user->ID, self::FORCE_RESET_META );
				delete_user_meta( (int) $user->ID, self::WARN_META );
			}
			return;
		}
		$wp_user = ! empty( $user->ID ) ? get_userdata( (int) $user->ID ) : null;
		$roles   = $wp_user ? (array) $wp_user->roles : array();
		if ( self::isEnforcedForRoles( $roles ) ) {
			$errors->add( 'wordgate_breached_password', self::messageForResult( $res ) );
		} elseif ( function_exists( 'wc_add_notice' ) ) {
			wc_add_notice( self::messageForResult( $res ), 'notice' );
		}
	}

	/**
	 * WooCommerce customer registration form.
	 *
	 * @param \WP_Error $errors
	 */
	public static function checkWooRegistration( $errors, $username = '', $email = '' ) {
		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$pass = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
		if ( '' === $pass ) {
			return $errors;
		}
		$res = self::checkPassword( $pass );
		if ( ! $res['compromised'] ) {
			return $errors;
		}
		$roles = array( 'customer', (string) get_option( 'default_role', 'subscriber' ) );
		if ( self::isEnforcedForRoles( $roles ) ) {
			$errors->add( 'wordgate_breached_password', self::messageForResult( $res ) );
		} elseif ( function_exists( 'wc_add_notice' ) ) {
			wc_add_notice( self::messageForResult( $res ), 'notice' );
		}
		return $errors;
	}

	public static function clearFlagsOnPasswordChange( $user_id, $old_user_data ) {
		$new = get_userdata( (int) $user_id );
		if ( $new && $old_user_data && $new->user_pass !== $old_user_data->user_pass ) {
			delete_user_meta( (int) $user_id, self::FORCE_RESET_META );
			delete_user_meta( (int) $user_id, self::WARN_META );
		}
	}

	public static function clearFlagsOnReset( $user ) {
		if ( $user instanceof \WP_User ) {
			delete_user_meta( $user->ID, self::FORCE_RESET_META );
			delete_user_meta( $user->ID, self::WARN_META );
		}
	}

	public static function enforcePasswordReset() {
		if ( wp_doing_ajax() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! get_user_meta( $user->ID, self::FORCE_RESET_META, true ) ) {
			return;
		}
		if ( ! self::isEnforcedForRoles( (array) $user->roles ) ) {
			return;
		}
		global $pagenow;
		if ( 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php#password' ) );
			exit;
		}
	}

	public static function adminNotices() {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		if ( get_user_meta( $user->ID, self::FORCE_RESET_META, true ) && self::isEnforcedForRoles( (array) $user->roles ) ) {
			printf(
				'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'Password change required:', 'wordgate' ),
				esc_html__( 'Your current password appears in a known data breach or common-password list. Set a new, unique password below before continuing.', 'wordgate' ),
				esc_url( admin_url( 'profile.php#password' ) ),
				esc_html__( 'Change password', 'wordgate' )
			);
			return;
		}
		if ( get_user_meta( $user->ID, self::WARN_META, true ) ) {
			printf(
				'<div class="notice notice-warning is-dismissible"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'Weak or breached password detected:', 'wordgate' ),
				esc_html__( 'Your password appeared in a known data breach or common-password list. We strongly recommend changing it.', 'wordgate' ),
				esc_url( admin_url( 'profile.php#password' ) ),
				esc_html__( 'Update password', 'wordgate' )
			);
		}
	}
}

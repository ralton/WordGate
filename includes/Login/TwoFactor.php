<?php
/**
 * TOTP two-factor authentication with recovery codes.
 *
 * Flow: the password is checked by WordPress as usual. If the user has 2FA
 * enabled, the auth cookie WordPress just set is cleared and the user is
 * redirected to an interstitial (wp-login.php?action=wordgate_2fa) holding a
 * short-lived, single-use token. Only a valid code completes the login.
 *
 * Storage note: the TOTP secret is stored in user meta unencrypted, like most
 * 2FA plugins. Encrypting it with the WordPress salts would lock every user
 * out the moment salts are rotated — which is exactly what you do after a
 * compromise.
 *
 * @package WordGate
 */

namespace WordGate\Login;

use WordGate\Log\EventLog;
use WordGate\Plugin;
use WordGate\Settings;

final class TwoFactor {

	const META          = 'wordgate_2fa';
	const PENDING_META  = 'wordgate_2fa_pending';
	const GRACE_META    = 'wordgate_2fa_grace_start';
	const TOKEN_COOKIE  = 'wordgate_2fa_token';
	const TOKEN_TTL     = 600;
	const MAX_ATTEMPTS  = 5;
	const RECOVERY_CODES = 10;

	/** @var bool Set while we complete a login ourselves, so wp_login is not intercepted twice. */
	private static $completing = false;
	/** @var int User ID whose initial session token is pending 2FA verification. */
	private static $pendingSessionUser = 0;
	/** @var string Session token minted by wp_set_auth_cookie() to destroy before 2FA. */
	private static $pendingSessionToken = '';

	public static function register() {
		add_action( 'set_auth_cookie', array( __CLASS__, 'captureSession' ), 1, 6 );
		add_filter( 'send_auth_cookies', array( __CLASS__, 'suppressAuthCookies' ), 1 );
		add_action( 'wp_login', array( __CLASS__, 'intercept' ), 1, 2 );
		add_action( 'login_form_wordgate_2fa', array( __CLASS__, 'handleInterstitial' ) );
		add_filter( 'authenticate', array( __CLASS__, 'blockPasswordOnlyApis' ), 60, 3 );
		add_filter( 'wp_login_errors', array( __CLASS__, 'expiredMessage' ) );

		add_action( 'show_user_profile', array( __CLASS__, 'renderProfile' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'renderProfile' ) );
		add_action( 'wp_ajax_wordgate_2fa_begin', array( __CLASS__, 'ajaxBegin' ) );
		add_action( 'wp_ajax_wordgate_2fa_enable', array( __CLASS__, 'ajaxEnable' ) );
		add_action( 'wp_ajax_wordgate_2fa_disable', array( __CLASS__, 'ajaxDisable' ) );
		add_action( 'wp_ajax_wordgate_2fa_recovery', array( __CLASS__, 'ajaxRegenerateRecovery' ) );

		add_action( 'admin_notices', array( __CLASS__, 'enforcementNotice' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce' ), 1 );
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'enforceRest' ), 90 );
	}

	/**
	 * True when this user is in the middle of a password login that must pass 2FA
	 * before any auth or bypass cookies may be emitted.
	 */
	public static function isIntercepting( $user_id ) {
		return ! self::$completing && self::isEnabled( (int) $user_id );
	}

	/**
	 * Capture the session token created by wp_set_auth_cookie() so intercept() can
	 * destroy it before redirecting to the 2FA screen.
	 */
	public static function captureSession( $auth_cookie, $expire, $expiration, $user_id, $scheme, $token ) {
		if ( self::isIntercepting( $user_id ) ) {
			self::$pendingSessionUser  = (int) $user_id;
			self::$pendingSessionToken = (string) $token;
		}
	}

	/**
	 * Prevent WordPress from emitting Set-Cookie headers for a 2FA-enabled account
	 * before the second factor has been verified.
	 */
	public static function suppressAuthCookies( $send ) {
		if ( ! self::$completing && self::$pendingSessionUser > 0 ) {
			return false;
		}
		return $send;
	}

	/* ---------------------------------------------------------------------
	 * State helpers
	 * ------------------------------------------------------------------- */

	public static function config( $user_id ) {
		$c = get_user_meta( $user_id, self::META, true );
		return is_array( $c ) ? $c : array();
	}

	public static function isEnabled( $user_id ) {
		if ( defined( 'WORDGATE_DISABLE_2FA' ) && WORDGATE_DISABLE_2FA ) {
			return false; // Emergency recovery switch (wp-config.php).
		}
		$c = self::config( $user_id );
		return ! empty( $c['enabled'] ) && ! empty( $c['secret'] );
	}

	public static function isRequired( \WP_User $user ) {
		$roles = (array) Settings::get( 'tfa_required_roles' );
		return (bool) array_intersect( $roles, (array) $user->roles );
	}

	public static function disable( $user_id ) {
		delete_user_meta( $user_id, self::META );
		delete_user_meta( $user_id, self::PENDING_META );
	}

	/**
	 * Verify a TOTP or recovery code and consume it. Returns 'totp', 'recovery' or false.
	 */
	public static function verifyAndConsume( $user_id, $code ) {
		$c = self::config( $user_id );
		if ( empty( $c['secret'] ) ) {
			return false;
		}
		$code = trim( (string) $code );

		$step = Totp::verify( $c['secret'], $code, 1, null, isset( $c['last_step'] ) ? (int) $c['last_step'] : null );
		if ( false !== $step ) {
			$c['last_step'] = $step;
			update_user_meta( $user_id, self::META, $c );
			return 'totp';
		}

		$normalized = strtolower( preg_replace( '/[^a-z0-9]/i', '', $code ) );
		if ( strlen( $normalized ) === 10 && ! empty( $c['recovery'] ) ) {
			foreach ( $c['recovery'] as $i => $hash ) {
				if ( wp_check_password( $normalized, $hash ) ) {
					unset( $c['recovery'][ $i ] );
					$c['recovery'] = array_values( $c['recovery'] );
					update_user_meta( $user_id, self::META, $c );
					return 'recovery';
				}
			}
		}
		return false;
	}

	/**
	 * @return string[] Plain-text codes, shown to the user once.
	 */
	private static function generateRecoveryCodes( $user_id ) {
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < self::RECOVERY_CODES; $i++ ) {
			$code     = strtolower( substr( Totp::base32Encode( random_bytes( 8 ) ), 0, 10 ) );
			$plain[]  = substr( $code, 0, 5 ) . '-' . substr( $code, 5 );
			$hashes[] = wp_hash_password( $code );
		}
		$c             = self::config( $user_id );
		$c['recovery'] = $hashes;
		update_user_meta( $user_id, self::META, $c );
		return $plain;
	}

	/* ---------------------------------------------------------------------
	 * Login interception
	 * ------------------------------------------------------------------- */

	/**
	 * @param string   $user_login
	 * @param \WP_User $user
	 */
	public static function intercept( $user_login, $user ) {
		if ( self::$completing || ! ( $user instanceof \WP_User ) || ! self::isEnabled( $user->ID ) ) {
			return;
		}

		// Destroy the session token WordPress just created in wp_set_auth_cookie()
		// so no valid session exists until the second factor succeeds.
		if ( '' !== self::$pendingSessionToken && self::$pendingSessionUser === $user->ID ) {
			\WP_Session_Tokens::get_instance( $user->ID )->destroy( self::$pendingSessionToken );
		} elseif ( function_exists( 'wp_destroy_current_session' ) ) {
			wp_destroy_current_session();
		}
		self::$pendingSessionUser  = 0;
		self::$pendingSessionToken = '';

		// Defense in depth: remove any Set-Cookie headers emitted earlier in this request.
		if ( ! headers_sent() && function_exists( 'header_remove' ) ) {
			header_remove( 'Set-Cookie' );
		}
		wp_clear_auth_cookie();

		// phpcs:disable WordPress.Security.NonceVerification
		$token   = bin2hex( random_bytes( 32 ) );
		$csrf    = bin2hex( random_bytes( 16 ) );
		$expires = time() + self::TOKEN_TTL;
		set_transient(
			'wordgate_2fa_' . hash( 'sha256', $token ),
			array(
				'user_id'     => $user->ID,
				'remember'    => ! empty( $_POST['rememberme'] ),
				'redirect_to' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '',
				'ip'          => Plugin::clientIp(),
				'csrf'        => $csrf,
				'expires'     => $expires,
			),
			self::TOKEN_TTL
		);
		// phpcs:enable

		self::setTokenCookie( $token, $expires );
		wp_safe_redirect( add_query_arg( 'action', 'wordgate_2fa', wp_login_url() ) );
		exit;
	}

	private static function setTokenCookie( $token, $expires ) {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			self::TOKEN_COOKIE,
			$token,
			array(
				'expires'  => (int) $expires,
				'path'     => '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	private static function clearTokenCookie() {
		self::setTokenCookie( '', time() - YEAR_IN_SECONDS );
		unset( $_COOKIE[ self::TOKEN_COOKIE ] );
	}

	/**
	 * Renders and processes the code-entry screen.
	 */
	public static function handleInterstitial() {
		nocache_headers();
		header( 'Referrer-Policy: no-referrer' );

		// phpcs:disable WordPress.Security.NonceVerification -- verified via per-session CSRF token below.
		$token = isset( $_COOKIE[ self::TOKEN_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::TOKEN_COOKIE ] ) ) : '';
		$hash  = '' !== $token ? hash( 'sha256', $token ) : '';
		$key   = '' !== $hash ? 'wordgate_2fa_' . $hash : '';
		$state = '' !== $key ? get_transient( $key ) : false;

		if ( ! is_array( $state ) || $state['ip'] !== Plugin::clientIp() || ( isset( $state['expires'] ) && (int) $state['expires'] < time() ) ) {
			if ( '' !== $key ) {
				delete_transient( $key );
			}
			self::clearTokenCookie();
			wp_safe_redirect( add_query_arg( 'wordgate_2fa', 'expired', wp_login_url() ) );
			exit;
		}

		$user  = get_user_by( 'id', $state['user_id'] );
		$error = '';

		if ( $user && 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST['wordgate_code'] ) ) {
			$csrf = isset( $_POST['wg_csrf'] ) ? sanitize_text_field( wp_unslash( $_POST['wg_csrf'] ) ) : '';
			if ( empty( $state['csrf'] ) || ! hash_equals( $state['csrf'], $csrf ) ) {
				$error = __( 'Invalid request. Please try again.', 'wordgate' );
			} else {
				$code   = sanitize_text_field( wp_unslash( $_POST['wordgate_code'] ) );
				$method = self::verifyAndConsume( $user->ID, $code );

				if ( $method ) {
					delete_transient( $key );
					Plugin::storage()->resetCounter( '2fa:' . $hash );
					self::clearTokenCookie();
					EventLog::add(
						'2fa_success',
						Plugin::clientIp(),
						array(
							'user_login' => $user->user_login,
							'reason'     => 'recovery' === $method ? 'Recovery code used' : '',
						),
						'recovery' === $method ? 'medium' : 'info'
					);

					self::$completing = true;
					wp_set_auth_cookie( $user->ID, (bool) $state['remember'] );
					do_action( 'wp_login', $user->user_login, $user ); // Let other plugins see the completed login.
					self::$completing = false;

					$redirect = $state['redirect_to'] ? $state['redirect_to'] : admin_url();
					$redirect = apply_filters( 'login_redirect', $redirect, $state['redirect_to'], $user );
					wp_safe_redirect( $redirect );
					exit;
				}

				$attempts = Plugin::storage()->increment( '2fa:' . $hash, self::TOKEN_TTL );
				EventLog::add( '2fa_failed', Plugin::clientIp(), array( 'user_login' => $user->user_login ), 'medium' );
				do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'wordgate_2fa_invalid' ) ); // Counts toward brute-force lockout.

				if ( $attempts >= self::MAX_ATTEMPTS ) {
					delete_transient( $key );
					Plugin::storage()->resetCounter( '2fa:' . $hash );
					self::clearTokenCookie();
					wp_safe_redirect( add_query_arg( 'wordgate_2fa', 'expired', wp_login_url() ) );
					exit;
				}
				$error = __( 'Invalid authentication code. Please try again.', 'wordgate' );
			}
		}
		// phpcs:enable

		login_header( __( 'Two-factor authentication', 'wordgate' ), '', $error ? new \WP_Error( 'wordgate_2fa', $error ) : null );
		?>
		<form name="wordgate_2fa" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', 'wordgate_2fa', wp_login_url() ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.', 'wordgate' ); ?></p>
			<p>
				<label for="wordgate_code"><?php esc_html_e( 'Authentication code', 'wordgate' ); ?></label>
				<input type="text" name="wordgate_code" id="wordgate_code" class="input" value="" size="20" inputmode="numeric" autocomplete="one-time-code" autofocus required />
			</p>
			<input type="hidden" name="wg_csrf" value="<?php echo esc_attr( $state['csrf'] ); ?>" />
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'wordgate' ); ?>" />
			</p>
		</form>
		<?php
		login_footer( 'wordgate_code' );
		exit;
	}

	/**
	 * @param \WP_Error $errors
	 */
	public static function expiredMessage( $errors ) {
		if ( isset( $_GET['wordgate_2fa'] ) && 'expired' === $_GET['wordgate_2fa'] ) { // phpcs:ignore WordPress.Security.NonceVerification
			$errors->add( 'wordgate_2fa_expired', __( 'Your two-factor session expired or had too many failed attempts. Please log in again.', 'wordgate' ) );
		}
		return $errors;
	}

	/**
	 * XML-RPC / HTTP basic auth with the account password would bypass 2FA.
	 * Application passwords (designed for API use) are still allowed.
	 */
	public static function blockPasswordOnlyApis( $user, $username = '', $password = '' ) {
		if ( ! ( $user instanceof \WP_User ) || ! self::isEnabled( $user->ID ) ) {
			return $user;
		}
		$is_api = ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST );
		if ( $is_api && ! did_action( 'application_password_did_authenticate' ) ) {
			return new \WP_Error( 'wordgate_2fa_api', __( 'This account uses two-factor authentication. Use an application password for API access.', 'wordgate' ) );
		}
		return $user;
	}

	/* ---------------------------------------------------------------------
	 * Enforcement
	 * ------------------------------------------------------------------- */

	private static function graceRemaining( \WP_User $user ) {
		$start = (int) get_user_meta( $user->ID, self::GRACE_META, true );
		if ( ! $start ) {
			$start = time();
			update_user_meta( $user->ID, self::GRACE_META, $start );
		}
		return $start + (int) Settings::get( 'tfa_grace_days' ) * DAY_IN_SECONDS - time();
	}

	public static function enforcementNotice() {
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! self::isRequired( $user ) || self::isEnabled( $user->ID ) ) {
			return;
		}
		$days = max( 0, (int) ceil( self::graceRemaining( $user ) / DAY_IN_SECONDS ) );
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
			esc_html__( 'Two-factor authentication is required for your account.', 'wordgate' ),
			/* translators: %d: days */
			esc_html( sprintf( _n( 'You have %d day left to set it up.', 'You have %d days left to set it up.', $days, 'wordgate' ), $days ) ),
			esc_url( admin_url( 'profile.php#wordgate-2fa' ) ),
			esc_html__( 'Set it up now', 'wordgate' )
		);
	}

	private static function isPastGrace( \WP_User $user ) {
		return $user->exists() && self::isRequired( $user ) && ! self::isEnabled( $user->ID ) && self::graceRemaining( $user ) <= 0;
	}

	/**
	 * After the grace period, users who must use 2FA can only reach their profile
	 * and WordGate's own 2FA setup endpoints.
	 */
	public static function enforce() {
		$user = wp_get_current_user();
		if ( ! self::isPastGrace( $user ) ) {
			return;
		}
		if ( wp_doing_ajax() ) {
			// phpcs:ignore WordPress.Security.NonceVerification
			$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
			if ( in_array( $action, array( 'wordgate_2fa_begin', 'wordgate_2fa_enable' ), true ) ) {
				return;
			}
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication is required before using this site.', 'wordgate' ) ), 403 );
		}
		global $pagenow;
		if ( 'profile.php' !== $pagenow ) {
			wp_safe_redirect( admin_url( 'profile.php#wordgate-2fa' ) );
			exit;
		}
	}

	/**
	 * Block cookie-authenticated REST requests when a user is past their 2FA grace period.
	 *
	 * @param \WP_Error|null|true $result
	 */
	public static function enforceRest( $result ) {
		if ( is_wp_error( $result ) || ! is_user_logged_in() || did_action( 'application_password_did_authenticate' ) ) {
			return $result;
		}
		if ( self::isPastGrace( wp_get_current_user() ) ) {
			return new \WP_Error(
				'wordgate_2fa_required',
				__( 'Two-factor authentication is required for your account. Set it up from your profile page first.', 'wordgate' ),
				array( 'status' => 403 )
			);
		}
		return $result;
	}

	/* ---------------------------------------------------------------------
	 * Profile UI + AJAX
	 * ------------------------------------------------------------------- */

	public static function renderProfile( \WP_User $user ) {
		$is_self = get_current_user_id() === $user->ID;
		if ( ! $is_self && ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$enabled   = self::isEnabled( $user->ID );
		$required  = self::isRequired( $user );
		$c         = self::config( $user->ID );
		$remaining = isset( $c['recovery'] ) ? count( $c['recovery'] ) : 0;
		wp_enqueue_script( 'wordgate-qrcode', WORDGATE_URL . 'assets/vendor/qrcode.js', array(), '2.0.4', true );
		wp_enqueue_script( 'wordgate-2fa', WORDGATE_URL . 'assets/two-factor.js', array( 'wordgate-qrcode' ), WORDGATE_VERSION, true );
		wp_localize_script(
			'wordgate-2fa',
			'WordGate2FA',
			array(
				'ajax'   => admin_url( 'admin-ajax.php' ),
				'nonce'  => wp_create_nonce( 'wordgate_2fa_' . $user->ID ),
				'userId' => $user->ID,
				'isSelf' => $is_self,
				'i18n'   => array(
					'confirmDisable'  => __( 'Turn off two-factor authentication for this account?', 'wordgate' ),
					'saveCodes'       => __( 'Save these recovery codes somewhere safe. Each can be used once if you lose your phone. They will not be shown again.', 'wordgate' ),
					'enabled'         => __( '✓ Two-factor authentication is on.', 'wordgate' ),
					'error'           => __( 'Something went wrong. Please try again.', 'wordgate' ),
					'passwordMissing' => __( 'Enter your current password to confirm this change.', 'wordgate' ),
				),
			)
		);
		?>
		<h2 id="wordgate-2fa"><?php esc_html_e( 'Two-factor authentication', 'wordgate' ); ?></h2>
		<table class="form-table" role="presentation"><tr><th><?php esc_html_e( 'Authenticator app', 'wordgate' ); ?></th><td>
			<div id="wordgate-2fa-box" data-enabled="<?php echo $enabled ? '1' : '0'; ?>">
			<?php if ( $enabled ) : ?>
				<p><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> <?php esc_html_e( 'Enabled.', 'wordgate' ); ?>
				<?php
				/* translators: %d: count */
				echo esc_html( sprintf( _n( '%d recovery code remaining.', '%d recovery codes remaining.', $remaining, 'wordgate' ), $remaining ) );
				?>
				</p>
				<?php if ( $is_self ) : ?>
					<p>
						<label for="wordgate-2fa-password"><?php esc_html_e( 'Current password (required to change 2FA settings):', 'wordgate' ); ?></label><br>
						<input type="password" id="wordgate-2fa-password" autocomplete="current-password" class="regular-text" />
					</p>
				<?php endif; ?>
				<p>
					<?php if ( $is_self ) : ?>
						<button type="button" class="button" id="wordgate-2fa-recovery"><?php esc_html_e( 'Generate new recovery codes', 'wordgate' ); ?></button>
					<?php endif; ?>
					<?php if ( ! $is_self || ! $required ) : ?>
						<button type="button" class="button" id="wordgate-2fa-disable"><?php esc_html_e( 'Turn off', 'wordgate' ); ?></button>
					<?php else : ?>
						<span class="description"><?php esc_html_e( 'Two-factor authentication is required for your role. Contact an administrator if you need it reset.', 'wordgate' ); ?></span>
					<?php endif; ?>
				</p>
			<?php elseif ( $is_self ) : ?>
				<p><?php esc_html_e( 'Protect your account with a 6-digit code from an authenticator app (1Password, Bitwarden, Google Authenticator, Authy, …) in addition to your password.', 'wordgate' ); ?></p>
				<p><button type="button" class="button button-primary" id="wordgate-2fa-begin"><?php esc_html_e( 'Set up two-factor authentication', 'wordgate' ); ?></button></p>
				<div id="wordgate-2fa-setup" hidden>
					<ol>
						<li><?php esc_html_e( 'Scan this QR code with your authenticator app:', 'wordgate' ); ?><div id="wordgate-2fa-qr" style="margin:8px 0"></div>
							<?php esc_html_e( 'Or enter this key manually:', 'wordgate' ); ?> <code id="wordgate-2fa-secret"></code></li>
						<li><label for="wordgate-2fa-code"><?php esc_html_e( 'Enter the 6-digit code it shows:', 'wordgate' ); ?></label>
							<input type="text" id="wordgate-2fa-code" inputmode="numeric" autocomplete="one-time-code" size="8" maxlength="7" />
							<button type="button" class="button button-primary" id="wordgate-2fa-enable"><?php esc_html_e( 'Activate', 'wordgate' ); ?></button></li>
					</ol>
				</div>
			<?php else : ?>
				<p><?php esc_html_e( 'Not enabled. Only the user can set this up.', 'wordgate' ); ?></p>
			<?php endif; ?>
				<p id="wordgate-2fa-msg" role="status"></p>
				<pre id="wordgate-2fa-codes" hidden></pre>
			</div>
		</td></tr></table>
		<?php
	}

	private static function ajaxGuard( $self_only ) {
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0;
		check_ajax_referer( 'wordgate_2fa_' . $user_id, 'nonce' );
		$is_self = get_current_user_id() === $user_id;
		if ( ( $self_only && ! $is_self ) || ( ! $is_self && ! current_user_can( 'edit_user', $user_id ) ) ) {
			wp_send_json_error( array( 'message' => __( 'Not allowed.', 'wordgate' ) ), 403 );
		}
		return $user_id;
	}

	public static function ajaxBegin() {
		$user_id = self::ajaxGuard( true );
		$user    = get_user_by( 'id', $user_id );
		$secret  = Totp::generateSecret();
		update_user_meta( $user_id, self::PENDING_META, $secret );
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		wp_send_json_success(
			array(
				'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
				'uri'    => Totp::provisioningUri( $secret, $user->user_login, '' !== $issuer ? $issuer : wp_parse_url( home_url(), PHP_URL_HOST ) ),
			)
		);
	}

	public static function ajaxEnable() {
		$user_id = self::ajaxGuard( true );
		$secret  = (string) get_user_meta( $user_id, self::PENDING_META, true );
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$step    = Totp::verify( $secret, $code, 1 );
		if ( '' === $secret || false === $step ) {
			wp_send_json_error( array( 'message' => __( 'That code is not valid. Check your phone\'s clock and try again.', 'wordgate' ) ) );
		}
		update_user_meta(
			$user_id,
			self::META,
			array(
				'enabled'    => true,
				'secret'     => $secret,
				'last_step'  => $step,
				'enabled_at' => time(),
			)
		);
		delete_user_meta( $user_id, self::PENDING_META );
		$codes = self::generateRecoveryCodes( $user_id );
		EventLog::add( '2fa_enabled', Plugin::clientIp(), array( 'user_login' => get_userdata( $user_id )->user_login ) );
		wp_send_json_success( array( 'codes' => $codes ) );
	}

	private static function verifyCurrentPassword( $user_id ) {
		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- nonce checked in ajaxGuard; passwords must not be sanitized.
		$password = isset( $_POST['password'] ) ? (string) wp_unslash( $_POST['password'] ) : '';
		$user     = get_user_by( 'id', $user_id );
		if ( ! $user || '' === $password || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Your current password is incorrect.', 'wordgate' ) ), 403 );
		}
	}

	public static function ajaxDisable() {
		$user_id = self::ajaxGuard( false );
		$is_self = get_current_user_id() === $user_id;
		$target  = get_user_by( 'id', $user_id );
		if ( $is_self ) {
			if ( $target && self::isRequired( $target ) ) {
				wp_send_json_error( array( 'message' => __( 'Two-factor authentication is required for your role. Contact an administrator to reset it.', 'wordgate' ) ), 403 );
			}
			self::verifyCurrentPassword( $user_id );
		}
		self::disable( $user_id );
		EventLog::add(
			'2fa_disabled',
			Plugin::clientIp(),
			array(
				'user_login' => $target ? $target->user_login : '',
				'reason'     => $is_self ? 'By user' : 'By ' . wp_get_current_user()->user_login,
			),
			'medium'
		);
		wp_send_json_success();
	}

	public static function ajaxRegenerateRecovery() {
		$user_id = self::ajaxGuard( true );
		if ( ! self::isEnabled( $user_id ) ) {
			wp_send_json_error();
		}
		self::verifyCurrentPassword( $user_id );
		wp_send_json_success( array( 'codes' => self::generateRecoveryCodes( $user_id ) ) );
	}
}

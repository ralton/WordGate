<?php
/**
 * WordPress hardening toggles: user enumeration, XML-RPC, version leaks,
 * file editor, security headers.
 *
 * @package WordGate
 */

namespace WordGate\Hardening;

use WordGate\Settings;

final class Hardening {

	public static function register() {
		$xmlrpc = Settings::get( 'xmlrpc' );
		if ( 'no_auth' === $xmlrpc ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		} elseif ( 'off' === $xmlrpc ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array', 999 );
			add_filter( 'wp_headers', array( __CLASS__, 'removePingbackHeader' ) );
			add_filter( 'pings_open', '__return_false', 999 );
		}

		if ( Settings::get( 'block_author_enum' ) ) {
			add_action( 'parse_request', array( __CLASS__, 'blockAuthorScan' ), 1 );
			add_filter( 'oembed_response_data', array( __CLASS__, 'stripOembedAuthor' ) );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'removeUserSitemap' ), 10, 2 );
		}

		if ( Settings::get( 'restrict_rest_users' ) ) {
			add_filter( 'rest_pre_dispatch', array( __CLASS__, 'restrictRestUsers' ), 10, 3 );
		}

		if ( Settings::get( 'hide_wp_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( Settings::get( 'disable_file_editor' ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'disableFileEditor' ), 10, 2 );
		}

		if ( Settings::get( 'security_headers' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'securityHeaders' ) );
			add_action( 'admin_init', array( __CLASS__, 'securityHeaders' ) );
			add_action( 'login_init', array( __CLASS__, 'securityHeaders' ) );
		}
	}

	public static function removePingbackHeader( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * /?author=1 redirects to /author/admin/, leaking login names.
	 *
	 * @param \WP $wp
	 */
	public static function blockAuthorScan( $wp ) {
		if ( is_user_logged_in() || is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( isset( $_GET['author'] ) || ( isset( $wp->query_vars['author'] ) && is_numeric( $wp->query_vars['author'] ) && empty( $wp->query_vars['author_name'] ) ) ) {
			wp_die( esc_html__( 'Forbidden.', 'wordgate' ), '', array( 'response' => 403 ) );
		}
	}

	public static function stripOembedAuthor( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	public static function removeUserSitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Hide /wp/v2/users from anonymous visitors.
	 */
	public static function restrictRestUsers( $result, $server, $request ) {
		if ( is_user_logged_in() ) {
			return $result;
		}
		if ( preg_match( '#^/wp/v2/users(?:/|$)#', $request->get_route() ) ) {
			return new \WP_Error( 'rest_forbidden', __( 'Sorry, you are not allowed to list users.', 'wordgate' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	public static function disableFileEditor( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	public static function securityHeaders() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}
}

<?php
/**
 * Main plugin container: wires modules to WordPress hooks.
 *
 * @package WordGate
 */

namespace WordGate;

use WordGate\Waf\Storage;

final class Plugin {

	/** @var Storage|null */
	private static $storage;

	public static function boot() {
		if ( get_option( 'wordgate_db_version' ) !== Installer::DB_VERSION ) {
			Installer::upgrade();
		}

		// Ensure the firewall has *something* even if the WAF loader was not
		// installed (e.g. read-only mu-plugins dir): run it now, late but useful.
		if ( ! defined( 'WORDGATE_WAF_LOADED' ) ) {
			include_once WORDGATE_DIR . '/waf/bootstrap.php';
		}

		Login\BruteForce::register();
		Login\TwoFactor::register();
		Login\AdminCookie::register();
		Hardening\Hardening::register();
		Firewall\NotFoundLimiter::register();
		Scanner\ScanRunner::register();
		Log\EventLog::register();
		Notifications::register();

		if ( is_admin() ) {
			Admin\Admin::register();
		}
	}

	public static function storage() {
		if ( null === self::$storage ) {
			self::$storage = new Storage( WORDGATE_DATA_DIR );
		}
		return self::$storage;
	}

	/**
	 * Client IP resolved with the same rules as the WAF.
	 */
	public static function clientIp() {
		static $ip = null;
		if ( null === $ip ) {
			$proxies = Settings::lines( 'trusted_proxies' );
			$ip      = Waf\IpUtil::clientIp( $_SERVER, (string) Settings::get( 'ip_source' ), $proxies ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}
		return $ip;
	}
}

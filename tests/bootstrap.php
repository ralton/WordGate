<?php
/**
 * PHPUnit bootstrap. Unit tests cover the WordPress-independent parts of
 * WordGate (WAF engine, TOTP, signatures) and run without WordPress.
 */

require_once __DIR__ . '/../vendor/autoload.php';

$wordgateTestDir = sys_get_temp_dir() . '/wordgate-tests-' . getmypid();
if ( ! is_dir( $wordgateTestDir ) ) {
	mkdir( $wordgateTestDir, 0777, true );
}
define( 'WORDGATE_DATA_DIR', $wordgateTestDir );
define( 'WORDGATE_TEST_DATA_DIR', $wordgateTestDir );

foreach ( array( 'IpUtil', 'Request', 'Transforms', 'SqliTokenizer', 'Rule', 'Storage', 'Response', 'Engine' ) as $class ) {
	require_once __DIR__ . '/../waf/src/' . $class . '.php';
}
require_once __DIR__ . '/../includes/Login/Totp.php';
require_once __DIR__ . '/../includes/Login/BruteForce.php';
require_once __DIR__ . '/../includes/Login/PasswordGuard.php';
require_once __DIR__ . '/../includes/Firewall/WafInstaller.php';
require_once __DIR__ . '/../includes/TamperMonitor.php';
require_once __DIR__ . '/../includes/Scanner/AdminAudit.php';
require_once __DIR__ . '/../includes/Scanner/DatabaseAudit.php';
require_once __DIR__ . '/../includes/Scanner/Signatures.php';
require_once __DIR__ . '/../includes/Scanner/Vulnerabilities.php';

// Minimal stand-ins for the few WordPress helpers the pure classes use.
if ( ! function_exists( 'esc_url_raw' ) ) {
	function esc_url_raw( $url ) {
		return filter_var( $url, FILTER_SANITIZE_URL );
	}
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $text ) {
		return trim( strip_tags( preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', (string) $text ) ) );
	}
}
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data ) {
		return json_encode( $data );
	}
}

register_shutdown_function(
	static function () use ( $wordgateTestDir ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $wordgateTestDir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
		foreach ( $it as $f ) {
			$f->isDir() ? rmdir( $f->getPathname() ) : unlink( $f->getPathname() );
		}
		rmdir( $wordgateTestDir );
	}
);

<?php
/**
 * WordGate WAF bootstrap.
 *
 * Loaded as early as possible — ideally via PHP's auto_prepend_file ("extended
 * protection", runs before WordPress and before every PHP file, including
 * vulnerable plugin files hit directly), or otherwise from a must-use plugin
 * ("basic protection", runs before regular plugins).
 *
 * The loader must define WORDGATE_DATA_DIR before including this file.
 * Nothing here may depend on WordPress.
 *
 * @package WordGate
 */

if ( defined( 'WORDGATE_WAF_LOADED' ) ) {
	return;
}
define( 'WORDGATE_WAF_LOADED', true );

// Never interfere with CLI (WP-CLI, cron run from the shell, tests).
if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
	return;
}

// Emergency kill switch: define( 'WORDGATE_WAF_DISABLE', true ) or create a
// file named "disable-waf" in the data directory.
if ( ( defined( 'WORDGATE_WAF_DISABLE' ) && WORDGATE_WAF_DISABLE ) || ! defined( 'WORDGATE_DATA_DIR' ) || file_exists( WORDGATE_DATA_DIR . '/disable-waf' ) ) {
	return;
}

require_once __DIR__ . '/src/IpUtil.php';
require_once __DIR__ . '/src/Request.php';
require_once __DIR__ . '/src/Transforms.php';
require_once __DIR__ . '/src/SqliTokenizer.php';
require_once __DIR__ . '/src/Rule.php';
require_once __DIR__ . '/src/Storage.php';
require_once __DIR__ . '/src/Response.php';
require_once __DIR__ . '/src/Engine.php';

try {
	$wordgate_storage = new \WordGate\Waf\Storage( WORDGATE_DATA_DIR );
	$wordgate_config  = $wordgate_storage->readConfig();

	if ( 'disabled' !== $wordgate_config['mode'] ) {
		$wordgate_storage->touchHeartbeat();
		$wordgate_engine = new \WordGate\Waf\Engine(
			$wordgate_storage,
			$wordgate_config,
			$wordgate_storage->loadRules( __DIR__ . '/rules/default.json' )
		);
		$GLOBALS['wordgate_waf_decision'] = $wordgate_engine->run(
			\WordGate\Waf\Request::fromGlobals( $wordgate_config['ip_source'], (array) $wordgate_config['trusted_proxies'] )
		);
	}
} catch ( \Throwable $e ) {
	// Fail open: a firewall bug must never take the site down.
	error_log( 'WordGate WAF error: ' . $e->getMessage() ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
}

unset( $wordgate_storage, $wordgate_config, $wordgate_engine );

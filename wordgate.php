<?php
/**
 * Plugin Name:       WordGate Security
 * Plugin URI:        https://github.com/ralton/wordgate
 * Description:       Open-source WordPress security: web application firewall, malware & integrity scanner, brute-force protection and two-factor authentication.
 * Version:           0.1.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WordGate contributors
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wordgate
 *
 * @package WordGate
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WORDGATE_VERSION', '0.1.3' );
define( 'WORDGATE_FILE', __FILE__ );
define( 'WORDGATE_DIR', __DIR__ );
define( 'WORDGATE_URL', plugin_dir_url( __FILE__ ) );

if ( ! defined( 'WORDGATE_DATA_DIR' ) ) {
	define( 'WORDGATE_DATA_DIR', WP_CONTENT_DIR . '/wordgate' );
}

spl_autoload_register(
	static function ( $class ) {
		if ( 0 !== strpos( $class, 'WordGate\\' ) ) {
			return;
		}
		$relative = substr( $class, strlen( 'WordGate\\' ) );
		if ( 0 === strpos( $relative, 'Waf\\' ) ) {
			$file = __DIR__ . '/waf/src/' . str_replace( '\\', '/', substr( $relative, 4 ) ) . '.php';
		} else {
			$file = __DIR__ . '/includes/' . str_replace( '\\', '/', $relative ) . '.php';
		}
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);

register_activation_hook( __FILE__, array( 'WordGate\\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WordGate\\Installer', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'WordGate\\Plugin', 'boot' ) );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command( 'wordgate', 'WordGate\\Cli\\Command' );
}

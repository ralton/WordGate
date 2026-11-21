<?php
/**
 * Installs the WAF loader.
 *
 * Basic:    a must-use plugin. Runs before regular plugins, but only for
 *           requests that load WordPress.
 * Extended: PHP auto_prepend_file. Runs before *every* PHP file, including
 *           vulnerable plugin files requested directly — the strongest mode.
 *
 * @package WordGate
 */

namespace WordGate\Firewall;

final class WafInstaller {

	const MARKER = 'WordGate WAF';

	public static function muPluginPath() {
		return WPMU_PLUGIN_DIR . '/wordgate-waf.php';
	}

	public static function stubPath() {
		return ABSPATH . 'wordgate-waf.php';
	}

	/**
	 * @return array{mode:string,loaded:bool,prepend:string,conflict:bool}
	 */
	public static function status() {
		$prepend  = (string) ini_get( 'auto_prepend_file' );
		$extended = '' !== $prepend && realpath( $prepend ) === realpath( self::stubPath() ) && file_exists( self::stubPath() );
		$mode     = 'none';
		if ( $extended ) {
			$mode = 'extended';
		} elseif ( file_exists( self::muPluginPath() ) ) {
			$mode = 'basic';
		}
		return array(
			'mode'     => $mode,
			'loaded'   => defined( 'WORDGATE_WAF_LOADED' ),
			'prepend'  => $prepend,
			'conflict' => '' !== $prepend && ! $extended,
		);
	}

	private static function loaderCode( $headerComment ) {
		$data = var_export( WORDGATE_DATA_DIR, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		$boot = var_export( WORDGATE_DIR . '/waf/bootstrap.php', true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		return "<?php\n{$headerComment}\n"
			. "if ( ! defined( 'WORDGATE_DATA_DIR' ) ) {\n\tdefine( 'WORDGATE_DATA_DIR', {$data} );\n}\n"
			. "if ( file_exists( {$boot} ) ) {\n\tinclude_once {$boot};\n}\n";
	}

	public static function installBasic() {
		if ( ! is_dir( WPMU_PLUGIN_DIR ) && ! wp_mkdir_p( WPMU_PLUGIN_DIR ) ) {
			return new \WP_Error( 'wordgate_mu', __( 'Could not create the mu-plugins directory.', 'wordgate' ) );
		}
		$code = self::loaderCode( "/**\n * Plugin Name: WordGate Firewall (loader)\n * Description: Loads the WordGate web application firewall early. Managed by WordGate; removed automatically on deactivation.\n */" );
		if ( false === @file_put_contents( self::muPluginPath(), $code ) ) { // phpcs:ignore
			return new \WP_Error( 'wordgate_mu', __( 'Could not write the firewall loader to mu-plugins. Check file permissions.', 'wordgate' ) );
		}
		return true;
	}

	public static function uninstallBasic() {
		if ( file_exists( self::muPluginPath() ) ) {
			@unlink( self::muPluginPath() ); // phpcs:ignore
		}
	}

	/**
	 * Detect which mechanism will set auto_prepend_file on this server.
	 */
	public static function detectServer() {
		$sapi     = PHP_SAPI;
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		if ( 'apache2handler' === $sapi ) {
			return 'apache-mod_php';
		}
		if ( 'litespeed' === $sapi || false !== strpos( $software, 'litespeed' ) ) {
			return 'litespeed';
		}
		if ( in_array( $sapi, array( 'fpm-fcgi', 'cgi-fcgi', 'cgi' ), true ) ) {
			return 'user-ini';
		}
		return 'manual';
	}

	/**
	 * Install extended protection.
	 *
	 * @param string $server apache-mod_php | litespeed | user-ini | manual.
	 * @return true|\WP_Error
	 */
	public static function installExtended( $server ) {
		$status = self::status();
		if ( $status['conflict'] ) {
			return new \WP_Error(
				'wordgate_conflict',
				sprintf(
					/* translators: %s: path of an existing auto_prepend_file */
					__( 'Another auto_prepend_file is already configured (%s). Remove it first or add WordGate to it manually.', 'wordgate' ),
					$status['prepend']
				)
			);
		}

		$stub = self::loaderCode( "// WordGate WAF loader (auto_prepend_file). Managed by WordGate." );
		if ( false === @file_put_contents( self::stubPath(), $stub ) ) { // phpcs:ignore
			return new \WP_Error( 'wordgate_stub', __( 'Could not write wordgate-waf.php to the WordPress root.', 'wordgate' ) );
		}

		$path = self::stubPath();
		switch ( $server ) {
			case 'apache-mod_php':
				$lines = array(
					'<IfModule mod_php.c>',
					"\tphp_value auto_prepend_file '{$path}'",
					'</IfModule>',
					'<IfModule mod_php7.c>',
					"\tphp_value auto_prepend_file '{$path}'",
					'</IfModule>',
				);
				return self::writeBlock( ABSPATH . '.htaccess', $lines, '#' );
			case 'litespeed':
				$lines = array(
					'<IfModule LiteSpeed>',
					"\tphp_value auto_prepend_file '{$path}'",
					'</IfModule>',
				);
				return self::writeBlock( ABSPATH . '.htaccess', $lines, '#' );
			case 'user-ini':
				$result = self::writeBlock( ABSPATH . '.user.ini', array( "auto_prepend_file = '{$path}'" ), ';' );
				if ( true === $result && file_exists( ABSPATH . '.htaccess' ) ) {
					// Keep .user.ini itself from being served.
					self::writeBlock( ABSPATH . '.htaccess', array( '<Files ".user.ini">', "\t<IfModule mod_authz_core.c>", "\t\tRequire all denied", "\t</IfModule>", '</Files>' ), '#' );
				}
				return $result;
		}
		return true; // Manual: the admin screen shows the php.ini line to add.
	}

	/**
	 * Remove extended protection.
	 *
	 * PHP caches .user.ini for user_ini.cache_ttl seconds (default 300). If we
	 * deleted the stub immediately, PHP would keep trying to prepend a missing
	 * file and every request would fatal. So we neuter the stub now and delete
	 * it later from cron.
	 */
	public static function uninstallExtended() {
		self::removeBlock( ABSPATH . '.htaccess', '#' );
		self::removeBlock( ABSPATH . '.user.ini', ';' );
		if ( file_exists( self::stubPath() ) ) {
			@file_put_contents( self::stubPath(), "<?php\n// WordGate WAF has been removed. This file is deleted automatically.\n" ); // phpcs:ignore
			$ttl = (int) ini_get( 'user_ini.cache_ttl' );
			wp_schedule_single_event( time() + max( 300, $ttl ) + 120, 'wordgate_delete_waf_stub' );
		}
	}

	public static function deleteStub() {
		$status = self::status();
		if ( 'extended' !== $status['mode'] && file_exists( self::stubPath() ) ) {
			@unlink( self::stubPath() ); // phpcs:ignore
		}
	}

	/**
	 * Insert / replace a marked block at the top of a config file.
	 */
	private static function writeBlock( $file, array $lines, $comment ) {
		$begin    = "{$comment} BEGIN " . self::MARKER;
		$end      = "{$comment} END " . self::MARKER;
		$existing = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore
		$existing = self::stripBlock( $existing, $comment );
		$block    = $begin . "\n" . implode( "\n", $lines ) . "\n" . $end . "\n";
		if ( false === @file_put_contents( $file, $block . $existing ) ) { // phpcs:ignore
			return new \WP_Error(
				'wordgate_write',
				/* translators: %s: file path */
				sprintf( __( 'Could not write %s. Check file permissions or configure auto_prepend_file manually.', 'wordgate' ), $file )
			);
		}
		return true;
	}

	private static function removeBlock( $file, $comment ) {
		if ( ! file_exists( $file ) ) {
			return;
		}
		$content = (string) file_get_contents( $file ); // phpcs:ignore
		$new     = self::stripBlock( $content, $comment );
		if ( $new !== $content ) {
			@file_put_contents( $file, $new ); // phpcs:ignore
		}
	}

	private static function stripBlock( $content, $comment ) {
		$c = preg_quote( $comment, '/' );
		$m = preg_quote( self::MARKER, '/' );
		return (string) preg_replace( "/{$c} BEGIN {$m}\n.*?{$c} END {$m}\n?/s", '', $content );
	}
}

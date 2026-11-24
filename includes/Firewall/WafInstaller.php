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

	const MARKER         = 'WordGate WAF';
	const UPLOADS_MARKER = 'WordGate Uploads Protection';

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
		if ( 'extended' !== get_option( \WordGate\TamperMonitor::EXPECTED_WAF_OPTION ) ) {
			\WordGate\TamperMonitor::setExpectedWafMode( 'basic' );
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
				$result = self::writeBlock( ABSPATH . '.htaccess', $lines, '#' );
				if ( true === $result ) {
					\WordGate\TamperMonitor::setExpectedWafMode( 'extended' );
				}
				return $result;
			case 'litespeed':
				$lines = array(
					'<IfModule LiteSpeed>',
					"\tphp_value auto_prepend_file '{$path}'",
					'</IfModule>',
				);
				$result = self::writeBlock( ABSPATH . '.htaccess', $lines, '#' );
				if ( true === $result ) {
					\WordGate\TamperMonitor::setExpectedWafMode( 'extended' );
				}
				return $result;
			case 'user-ini':
				$result = self::writeBlock( ABSPATH . '.user.ini', array( "auto_prepend_file = '{$path}'" ), ';' );
				if ( true === $result && file_exists( ABSPATH . '.htaccess' ) ) {
					// Keep .user.ini itself from being served.
					self::writeBlock( ABSPATH . '.htaccess', array( '<Files ".user.ini">', "\t<IfModule mod_authz_core.c>", "\t\tRequire all denied", "\t</IfModule>", '</Files>' ), '#' );
				}
				if ( true === $result ) {
					\WordGate\TamperMonitor::setExpectedWafMode( 'extended' );
				}
				return $result;
		}
		return true; // Manual: the admin screen shows the php.ini line to add.
	}

	/**
	 * Remove extended protection.
	 *
	 * PHP caches .user.ini for user_ini.cache_ttl seconds (default 300). If we
	 * deleted an actively prepended .user.ini stub immediately, PHP would keep
	 * trying to prepend a missing file and every request would fatal. When the
	 * stub is not actively prepended via .user.ini, delete it right away;
	 * otherwise neuter it now and schedule deletion after the cache TTL.
	 *
	 * @param bool $deactivating When true (plugin deactivation), do not leave an
	 *                           orphaned cron event that can never fire.
	 */
	public static function uninstallExtended( $deactivating = false ) {
		$status        = self::status();
		$activeUserIni = 'extended' === $status['mode'] && 'user-ini' === self::detectServer();

		self::removeBlock( ABSPATH . '.htaccess', '#' );
		self::removeBlock( ABSPATH . '.user.ini', ';' );
		\WordGate\TamperMonitor::setExpectedWafMode( $deactivating ? '' : ( file_exists( self::muPluginPath() ) ? 'basic' : '' ) );

		if ( file_exists( self::stubPath() ) ) {
			if ( ! $activeUserIni ) {
				@unlink( self::stubPath() ); // phpcs:ignore
				wp_clear_scheduled_hook( 'wordgate_delete_waf_stub' );
				return;
			}
			@file_put_contents( self::stubPath(), "<?php\n// WordGate WAF has been removed. This file is deleted automatically.\n" ); // phpcs:ignore
			if ( ! $deactivating ) {
				$ttl = (int) ini_get( 'user_ini.cache_ttl' );
				wp_schedule_single_event( time() + max( 300, $ttl ) + 120, 'wordgate_delete_waf_stub' );
			}
		}
	}

	/**
	 * Nginx deny rule needed because Nginx ignores .htaccess files.
	 */
	public static function nginxSnippet() {
		return "location ~* /(\\.user\\.ini|wp-content/wordgate/) {\n\tdeny all;\n}";
	}

	public static function deleteStub() {
		$status = self::status();
		if ( 'extended' !== $status['mode'] && file_exists( self::stubPath() ) ) {
			@unlink( self::stubPath() ); // phpcs:ignore
		}
	}

	/* ---------------------------------------------------------------------
	 * Uploads PHP execution protection
	 * ------------------------------------------------------------------- */

	public static function uploadsHtaccessPath() {
		$uploads = wp_get_upload_dir();
		return rtrim( (string) $uploads['basedir'], '/\\' ) . '/.htaccess';
	}

	/**
	 * Apache 2.2 and 2.4 rules denying PHP execution in wp-content/uploads/.
	 *
	 * @return string[]
	 */
	public static function uploadsHtaccessLines() {
		return array(
			'<FilesMatch "(?i)\.(?:php\d?|phtml|phar|pht|phps)(?:\.|$)">',
			"\t<IfModule mod_authz_core.c>",
			"\t\tRequire all denied",
			"\t</IfModule>",
			"\t<IfModule !mod_authz_core.c>",
			"\t\tOrder deny,allow",
			"\t\tDeny from all",
			"\t</IfModule>",
			'</FilesMatch>',
		);
	}

	public static function uploadsNginxSnippet( $uploadsRelPath = null ) {
		if ( null === $uploadsRelPath ) {
			$uploads        = function_exists( 'wp_get_upload_dir' ) ? wp_get_upload_dir() : array();
			$url_path       = ! empty( $uploads['baseurl'] ) ? (string) parse_url( $uploads['baseurl'], PHP_URL_PATH ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
			$uploadsRelPath = '' !== $url_path ? '/' . trim( $url_path, '/' ) . '/' : '/wp-content/uploads/';
		}
		return 'location ~* ^' . $uploadsRelPath . ".*\\.(?:php\\d?|phtml|phar|pht|phps)(?:\\.|$) {\n\tdeny all;\n}";
	}

	public static function isUploadsPhpDisabled( $htaccessPath = null ) {
		$file = null === $htaccessPath ? self::uploadsHtaccessPath() : $htaccessPath;
		if ( ! file_exists( $file ) ) {
			return false;
		}
		$content = (string) @file_get_contents( $file ); // phpcs:ignore
		return false !== strpos( $content, '# BEGIN ' . self::UPLOADS_MARKER );
	}

	/**
	 * @return true|\WP_Error|false
	 */
	public static function enableUploadsPhpProtection( $htaccessPath = null ) {
		$file = null === $htaccessPath ? self::uploadsHtaccessPath() : $htaccessPath;
		$dir  = dirname( $file );
		if ( ! is_dir( $dir ) && ! ( function_exists( 'wp_mkdir_p' ) ? wp_mkdir_p( $dir ) : @mkdir( $dir, 0755, true ) ) ) { // phpcs:ignore
			$msg = function_exists( '__' ) ? __( 'Could not create the uploads directory.', 'wordgate' ) : 'Could not create the uploads directory.';
			return class_exists( '\\WP_Error' ) ? new \WP_Error( 'wordgate_uploads_dir', $msg ) : false;
		}
		return self::writeBlock( $file, self::uploadsHtaccessLines(), '#', self::UPLOADS_MARKER );
	}

	public static function disableUploadsPhpProtection( $htaccessPath = null ) {
		$file = null === $htaccessPath ? self::uploadsHtaccessPath() : $htaccessPath;
		self::removeBlock( $file, '#', self::UPLOADS_MARKER );
	}

	/**
	 * Interpret the HTTP response of an uploads PHP execution probe.
	 *
	 * @return array{status:string,http_code:int}
	 */
	public static function evaluateUploadsProbe( $httpCode, $body, $wordgateHeader, $marker ) {
		$httpCode = (int) $httpCode;
		if ( false !== strpos( (string) $body, (string) $marker ) ) {
			return array( 'status' => 'executed', 'http_code' => $httpCode );
		}
		if ( '' !== trim( (string) $wordgateHeader ) ) {
			return array( 'status' => 'blocked_by_waf_only', 'http_code' => $httpCode );
		}
		if ( in_array( $httpCode, array( 403, 404, 405, 410 ), true ) ) {
			return array( 'status' => 'blocked_by_server', 'http_code' => $httpCode );
		}
		if ( 200 === $httpCode ) {
			return array( 'status' => 'served_raw', 'http_code' => $httpCode );
		}
		return array( 'status' => 'unknown', 'http_code' => $httpCode );
	}

	/**
	 * Self-test: drop a harmless probe PHP file into uploads, request it over
	 * HTTP, confirm PHP does not execute it, and always remove the probe.
	 *
	 * @return array{status:string,http_code:int,message:string}
	 */
	public static function testUploadsPhpExecution() {
		$uploads = wp_get_upload_dir();
		$dir     = rtrim( (string) $uploads['basedir'], '/\\' );
		$baseUrl = rtrim( (string) $uploads['baseurl'], '/' );
		if ( '' === $dir || ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return array(
				'status'    => 'error',
				'http_code' => 0,
				'message'   => __( 'Could not write a temporary probe file to the uploads directory. Check directory permissions.', 'wordgate' ),
			);
		}

		$token = bin2hex( random_bytes( 8 ) );
		$name  = 'wordgate-probe-' . $token . '.php';
		$path  = $dir . '/' . $name;
		$code  = "<?php echo 'WORDGATE_PROBE_{$token}_' . ( 19 + 23 );\n";
		if ( false === @file_put_contents( $path, $code ) ) { // phpcs:ignore
			return array(
				'status'    => 'error',
				'http_code' => 0,
				'message'   => __( 'Could not write a temporary probe file to the uploads directory.', 'wordgate' ),
			);
		}

		try {
			$res = wp_remote_get(
				$baseUrl . '/' . $name,
				array(
					'timeout'     => 10,
					'redirection' => 0,
				)
			);
		} finally {
			if ( file_exists( $path ) ) {
				@unlink( $path ); // phpcs:ignore
			}
		}

		if ( is_wp_error( $res ) ) {
			return array(
				'status'    => 'error',
				'http_code' => 0,
				/* translators: %s: error message */
				'message'   => sprintf( __( 'Self-test could not reach the uploads URL: %s', 'wordgate' ), $res->get_error_message() ),
			);
		}

		$eval = self::evaluateUploadsProbe(
			wp_remote_retrieve_response_code( $res ),
			wp_remote_retrieve_body( $res ),
			wp_remote_retrieve_header( $res, 'x-wordgate' ),
			'WORDGATE_PROBE_' . $token . '_42'
		);

		switch ( $eval['status'] ) {
			case 'blocked_by_server':
				/* translators: %d: HTTP status code */
				$msg = sprintf( __( 'Protected: the web server refused the probe PHP file (HTTP %d) before PHP ran.', 'wordgate' ), $eval['http_code'] );
				break;
			case 'blocked_by_waf_only':
				$msg = __( 'Partial protection: the web server passed the probe file to PHP, and WordGate\'s firewall blocked it. On Nginx (or Apache with AllowOverride None), add the Nginx rule below for server-level protection.', 'wordgate' );
				break;
			case 'served_raw':
				$msg = __( 'Not executed: the probe was served as plain text rather than executed as PHP. Adding a server deny rule is still recommended.', 'wordgate' );
				break;
			case 'executed':
				$msg = __( 'Vulnerable: PHP executed the probe file inside uploads! Your web server ignored .htaccess — configure the Nginx / server deny rule below.', 'wordgate' );
				break;
			default:
				/* translators: %d: HTTP status code */
				$msg = sprintf( __( 'Unexpected HTTP %d response during self-test; verify your server configuration manually.', 'wordgate' ), $eval['http_code'] );
		}

		return array(
			'status'    => $eval['status'],
			'http_code' => $eval['http_code'],
			'message'   => $msg,
		);
	}

	/**
	 * Insert / replace a marked block at the top of a config file.
	 */
	public static function writeBlock( $file, array $lines, $comment, $marker = self::MARKER ) {
		$begin    = "{$comment} BEGIN " . $marker;
		$end      = "{$comment} END " . $marker;
		$existing = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore
		$existing = self::stripBlock( $existing, $comment, $marker );
		$block    = $begin . "\n" . implode( "\n", $lines ) . "\n" . $end . "\n";
		if ( false === @file_put_contents( $file, $block . $existing ) ) { // phpcs:ignore
			$msg = sprintf( 'Could not write %s. Check file permissions or configure this manually.', $file );
			if ( function_exists( '__' ) ) {
				/* translators: %s: file path */
				$msg = sprintf( __( 'Could not write %s. Check file permissions or configure auto_prepend_file manually.', 'wordgate' ), $file );
			}
			return class_exists( '\\WP_Error' ) ? new \WP_Error( 'wordgate_write', $msg ) : false;
		}
		return true;
	}

	public static function removeBlock( $file, $comment, $marker = self::MARKER ) {
		if ( ! file_exists( $file ) ) {
			return;
		}
		$content = (string) file_get_contents( $file ); // phpcs:ignore
		$new     = self::stripBlock( $content, $comment, $marker );
		if ( $new !== $content ) {
			@file_put_contents( $file, $new ); // phpcs:ignore
		}
	}

	public static function stripBlock( $content, $comment, $marker = self::MARKER ) {
		$c = preg_quote( $comment, '/' );
		$m = preg_quote( $marker, '/' );
		return (string) preg_replace( "/{$c} BEGIN {$m}\n.*?{$c} END {$m}\n?/s", '', $content );
	}
}

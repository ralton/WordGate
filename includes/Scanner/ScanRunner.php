<?php
/**
 * Resumable, time-boxed security scan.
 *
 * Shared hosts kill PHP after 30–60 seconds, so the scan is a state machine
 * persisted in an option. Each step() works for a few seconds and returns;
 * the admin UI (AJAX), WP-Cron or WP-CLI keep calling it until done.
 *
 * Phases:
 *   core     Compare WordPress core files with official checksums; find unknown files in core dirs.
 *   plugins  Compare wordpress.org plugins with official checksums.
 *   vulns    Look up installed plugin/theme versions in the open WPVulnerability database.
 *   index    List files that still need signature scanning (everything not verified above).
 *   files    Malware signature scan + PHP files in uploads.
 *   checks   Configuration checks (updates, debug mode, admin username, ...).
 *   finish   Resolve issues that have disappeared, notify.
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

use WordGate\Log\EventLog;
use WordGate\Notifications;
use WordGate\Plugin;
use WordGate\Settings;

final class ScanRunner {

	const STATE  = 'wordgate_scan_state';
	const LAST   = 'wordgate_last_scan';
	const PHASES = array( 'core', 'plugins', 'vulns', 'index', 'files', 'checks', 'finish' );

	/** @var array */
	private static $state;
	/** @var array<string,bool>|null */
	private static $verified;
	/** @var Signatures|null */
	private static $signatures;

	public static function register() {
		add_action( 'wordgate_daily', array( __CLASS__, 'maybeScheduled' ) );
		add_action( 'wordgate_scan_continue', array( __CLASS__, 'cronStep' ) );
		add_action( 'wordgate_delete_waf_stub', array( \WordGate\Firewall\WafInstaller::class, 'deleteStub' ) );
		add_action( 'wp_ajax_wordgate_scan_start', array( __CLASS__, 'ajaxStart' ) );
		add_action( 'wp_ajax_wordgate_scan_step', array( __CLASS__, 'ajaxStep' ) );
	}

	/* ---------------------------------------------------------------------
	 * Public API
	 * ------------------------------------------------------------------- */

	public static function state() {
		$s = get_option( self::STATE );
		return is_array( $s ) ? $s : array( 'status' => 'idle' );
	}

	public static function isRunning() {
		$s = self::state();
		// A scan untouched for 15 minutes is considered dead and may be restarted.
		return 'running' === $s['status'] && time() - (int) $s['updated'] < 15 * MINUTE_IN_SECONDS;
	}

	public static function start( $source = 'manual' ) {
		if ( self::isRunning() ) {
			return self::state();
		}
		self::cleanupTemp();
		self::$state = array(
			'id'      => time(),
			'status'  => 'running',
			'source'  => $source,
			'phase'   => 'core',
			'cursor'  => 0,
			'started' => time(),
			'updated' => time(),
			'stats'   => array(
				'files_total'      => 0,
				'files_scanned'    => 0,
				'issues'           => 0,
				'new_issues'       => 0,
				'new_issue_titles' => array(),
			),
			'notes'   => array(),
		);
		self::save();
		EventLog::add( 'scan_started', '', array( 'reason' => $source ) );
		return self::$state;
	}

	/**
	 * Run the scan for up to $budget seconds.
	 */
	public static function step( $budget = null ) {
		if ( get_transient( 'wordgate_scan_lock' ) ) {
			return self::state();
		}
		set_transient( 'wordgate_scan_lock', 1, 120 );

		self::$state = self::state();
		if ( 'running' !== self::$state['status'] ) {
			delete_transient( 'wordgate_scan_lock' );
			return self::$state;
		}

		$deadline = microtime( true ) + ( null === $budget ? self::defaultBudget() : (float) $budget );
		try {
			while ( 'running' === self::$state['status'] && microtime( true ) < $deadline ) {
				$phase = self::$state['phase'];
				$done  = call_user_func( array( __CLASS__, 'phase' . ucfirst( $phase ) ), $deadline );
				if ( $done ) {
					$next                  = array_search( $phase, self::PHASES, true ) + 1;
					self::$state['phase']  = isset( self::PHASES[ $next ] ) ? self::PHASES[ $next ] : 'finish';
					self::$state['cursor'] = 0;
				}
				self::$state['updated'] = time();
				self::save();
			}
		} catch ( \Throwable $e ) {
			self::$state['status'] = 'failed';
			self::$state['notes'][] = 'Scan failed: ' . $e->getMessage();
			self::save();
		}
		delete_transient( 'wordgate_scan_lock' );
		return self::$state;
	}

	public static function runToCompletion( ?callable $progress = null ) {
		self::start( 'cli' );
		do {
			$s = self::step( 25 );
			if ( $progress ) {
				$progress( $s );
			}
		} while ( 'running' === $s['status'] );
		return $s;
	}

	public static function maybeScheduled() {
		$schedule = Settings::get( 'scan_schedule' );
		if ( 'off' === $schedule ) {
			return;
		}
		$last     = get_option( self::LAST );
		$interval = 'weekly' === $schedule ? WEEK_IN_SECONDS : DAY_IN_SECONDS;
		if ( is_array( $last ) && time() - (int) $last['finished'] < $interval - HOUR_IN_SECONDS ) {
			return;
		}
		self::start( 'scheduled' );
		wp_schedule_single_event( time() + 5, 'wordgate_scan_continue' );
	}

	public static function cronStep() {
		$s = self::step( min( 20, self::defaultBudget() ) );
		if ( 'running' === $s['status'] ) {
			wp_schedule_single_event( time() + 5, 'wordgate_scan_continue' );
		}
	}

	public static function ajaxStart() {
		check_ajax_referer( 'wordgate_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		self::start( 'manual' );
		wp_send_json_success( self::publicState( self::step( 8 ) ) );
	}

	public static function ajaxStep() {
		check_ajax_referer( 'wordgate_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		wp_send_json_success( self::publicState( self::step( 10 ) ) );
	}

	public static function publicState( array $s ) {
		$labels = array(
			'core'    => __( 'Checking WordPress core files', 'wordgate' ),
			'plugins' => __( 'Checking plugin files', 'wordgate' ),
			'vulns'   => __( 'Checking for known vulnerabilities', 'wordgate' ),
			'index'   => __( 'Indexing files', 'wordgate' ),
			'files'   => __( 'Scanning files for malware', 'wordgate' ),
			'checks'  => __( 'Checking configuration', 'wordgate' ),
			'finish'  => __( 'Finishing', 'wordgate' ),
		);
		return array(
			'status' => $s['status'],
			'phase'  => isset( $s['phase'], $labels[ $s['phase'] ] ) ? $labels[ $s['phase'] ] : '',
			'index'  => isset( $s['phase'] ) ? array_search( $s['phase'], self::PHASES, true ) : 0,
			'total'  => count( self::PHASES ),
			'stats'  => isset( $s['stats'] ) ? $s['stats'] : array(),
			'notes'  => isset( $s['notes'] ) ? $s['notes'] : array(),
		);
	}

	/* ---------------------------------------------------------------------
	 * Phases — each returns true when complete.
	 * ------------------------------------------------------------------- */

	private static function phaseCore( $deadline ) {
		global $wp_version;
		$checksums = self::coreChecksums( $wp_version, get_locale() );
		if ( ! $checksums ) {
			self::note( __( 'Could not download WordPress core checksums; core integrity was not checked.', 'wordgate' ) );
			return true;
		}

		$skip_missing = array( 'readme.html', 'license.txt', 'wp-config-sample.php', 'wp-admin/install.php' );
		$verified     = array();
		foreach ( $checksums as $rel => $md5 ) {
			$path = ABSPATH . $rel;
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				$path = WP_CONTENT_DIR . substr( $rel, 10 );
				if ( is_file( $path ) && md5_file( $path ) === $md5 ) {
					$verified[] = $path;
				}
				continue;
			}
			if ( ! is_file( $path ) ) {
				if ( ! in_array( $rel, $skip_missing, true ) ) {
					self::issue( 'core_missing', 'low', sprintf( __( 'WordPress core file missing: %s', 'wordgate' ), $rel ), __( 'A file that ships with WordPress is missing. Reinstalling WordPress from Dashboard → Updates restores it.', 'wordgate' ), $path );
				}
				continue;
			}
			if ( md5_file( $path ) !== $md5 ) {
				self::issue(
					'core_modified',
					'high',
					/* translators: %s: file path */
					sprintf( __( 'WordPress core file modified: %s', 'wordgate' ), $rel ),
					__( 'This file differs from the official WordPress release. Core files should never be edited; modifications are a common sign of compromise. Review the change, then restore the original.', 'wordgate' ),
					$path,
					array(
						'rel'     => $rel,
						'md5'     => $md5,
						'version' => $wp_version,
						'repair'  => 'core',
					)
				);
				continue;
			}
			$verified[] = $path;
		}
		self::addVerified( $verified );

		// Files in wp-admin / wp-includes that are not part of WordPress.
		$skip_names = array( 'error_log', '.DS_Store', 'php_errorlog', '.htaccess' );
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( self::walk( ABSPATH . $dir ) as $path ) {
				$rel = substr( $path, strlen( ABSPATH ) );
				if ( isset( $checksums[ $rel ] ) || in_array( basename( $path ), $skip_names, true ) ) {
					continue;
				}
				$is_code = self::isExecutable( $path );
				self::issue(
					'core_unknown',
					$is_code ? 'high' : 'medium',
					/* translators: %s: file path */
					sprintf( __( 'Unknown file in WordPress core directory: %s', 'wordgate' ), $rel ),
					__( 'This file is not part of WordPress but sits in a core directory, a favourite hiding place for backdoors. If you did not put it there, delete it.', 'wordgate' ),
					$path,
					array( 'repair' => 'delete' )
				);
			}
		}

		// Unknown PHP files in the site root (e.g. "wp-l0gin.php").
		$root_ok = array( 'wp-config.php', 'wordgate-waf.php' );
		foreach ( (array) glob( ABSPATH . '*.php' ) as $path ) {
			$rel = basename( $path );
			if ( ! isset( $checksums[ $rel ] ) && ! in_array( $rel, $root_ok, true ) ) {
				// Low on its own: hosts and other apps often put files here. If the file
				// also matches a malware signature, the files phase reports that separately.
				self::issue(
					'root_unknown',
					'low',
					/* translators: %s: file name */
					sprintf( __( 'Unknown PHP file in site root: %s', 'wordgate' ), $rel ),
					__( 'This PHP file is not part of WordPress. Hosting companies and other applications sometimes place files here, so it may be harmless — but attackers also drop backdoors in the site root. If you do not recognise it, open it and check, or ask your host. Its fingerprint (SHA-256) lets you compare it with the same file on your other sites.', 'wordgate' ),
					$path,
					array(
						'repair' => 'delete',
						'size'   => (int) filesize( $path ),
						'mtime'  => (int) filemtime( $path ),
						'sha256' => (string) hash_file( 'sha256', $path ),
					)
				);
			}
		}
		return true;
	}

	private static function phasePlugins( $deadline ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = array_keys( get_plugins() );
		$all     = get_plugins();
		while ( self::$state['cursor'] < count( $plugins ) ) {
			if ( microtime( true ) > $deadline ) {
				return false;
			}
			$file = $plugins[ self::$state['cursor']++ ];
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				continue;
			}
			$version   = $all[ $file ]['Version'];
			$checksums = self::pluginChecksums( $slug, $version );
			if ( null === $checksums ) {
				continue; // Not on wordpress.org (premium/custom) — covered by the malware scan.
			}
			$base     = WP_PLUGIN_DIR . '/' . $slug . '/';
			$verified = array();
			foreach ( $checksums as $rel => $hashes ) {
				$path = $base . $rel;
				if ( ! is_file( $path ) ) {
					continue;
				}
				$expected = isset( $hashes['md5'] ) ? (array) $hashes['md5'] : array();
				if ( in_array( md5_file( $path ), $expected, true ) ) {
					$verified[] = $path;
				} elseif ( self::isExecutable( $path ) || preg_match( '/\.(js|html?)$/i', $path ) ) {
					self::issue(
						'plugin_modified',
						'high',
						/* translators: 1: plugin name, 2: file */
						sprintf( __( 'Plugin file modified: %1$s — %2$s', 'wordgate' ), $all[ $file ]['Name'], $rel ),
						__( 'This file differs from the version published on wordpress.org. Unless you edited it yourself, it may have been tampered with. Restore the original or reinstall the plugin.', 'wordgate' ),
						$path,
						array(
							'slug'    => $slug,
							'version' => $version,
							'rel'     => $rel,
							'md5'     => $expected,
							'repair'  => 'plugin',
						)
					);
				}
			}
			self::addVerified( $verified );
		}
		return true;
	}

	private static function phaseVulns( $deadline ) {
		if ( ! Settings::get( 'vuln_check' ) ) {
			return true;
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( 0 === (int) self::$state['cursor'] ) {
			self::refreshUpdateData();
		}
		$latest = self::latestVersions();
		$items  = array();
		foreach ( get_plugins() as $file => $p ) {
			$slug = dirname( $file );
			if ( '.' !== $slug ) {
				$items[] = array( 'plugin', $slug, $p['Version'], $p['Name'], is_plugin_active( $file ) );
			}
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$items[] = array( 'theme', $slug, $theme->get( 'Version' ), $theme->get( 'Name' ), get_stylesheet() === $slug || get_template() === $slug );
		}

		while ( self::$state['cursor'] < count( $items ) ) {
			if ( microtime( true ) > $deadline ) {
				return false;
			}
			list( $kind, $slug, $version, $name, $active ) = $items[ self::$state['cursor']++ ];
			$data = Vulnerabilities::lookup( $kind, $slug );
			if ( ! $data ) {
				continue;
			}
			$summary = Vulnerabilities::summarize( $data, $version, isset( $latest[ $kind ][ $slug ] ) ? $latest[ $kind ][ $slug ] : '' );
			if ( $summary ) {
				$n = $summary['count'];
				if ( 1 === $n ) {
					/* translators: 1: plugin/theme name, 2: version, 3: vulnerability title */
					$title = sprintf( __( '%1$s %2$s has a known vulnerability: %3$s', 'wordgate' ), $name, $version, $summary['items'][0]['title'] );
				} else {
					/* translators: 1: plugin/theme name, 2: version, 3: count */
					$title = sprintf( __( '%1$s %2$s has %3$d known vulnerabilities', 'wordgate' ), $name, $version, $n );
				}
				if ( $summary['fixed_in'] ) {
					/* translators: %s: version */
					$advice = sprintf( __( 'Update to version %s or later.', 'wordgate' ), $summary['fixed_in'] );
				} elseif ( $summary['newer_than'] ) {
					/* translators: %s: version */
					$advice = sprintf( __( 'Update to the latest version (newer than %s).', 'wordgate' ), $summary['newer_than'] );
				} else {
					$advice = __( 'No fixed version is available. Consider removing it and finding an alternative.', 'wordgate' );
				}
				if ( $summary['unfixed'] && ( $summary['fixed_in'] || $summary['newer_than'] ) ) {
					$advice .= ' ' . __( 'Some of these have no fix yet; consider replacing this component.', 'wordgate' );
				}
				if ( ! $active ) {
					$advice .= ' ' . __( 'It is inactive, but its files can still be attacked directly — delete it if you do not use it.', 'wordgate' );
				}
				self::issue(
					'vulnerable_' . $kind,
					$summary['severity'],
					$title,
					$advice,
					'',
					array(
						'kind'            => $kind,
						'slug'            => $slug,
						'version'         => $version,
						'fixed_in'        => $summary['fixed_in'],
						'vulnerabilities' => $summary['items'],
					),
					$kind . ':' . $slug
				);
			}
			if ( 'plugin' === $kind && ! empty( $data['closed'] ) ) {
				self::issue(
					'abandoned_plugin',
					'medium',
					/* translators: %s: plugin name */
					sprintf( __( 'Plugin removed from wordpress.org: %s', 'wordgate' ), $name ),
					__( 'This plugin has been closed on wordpress.org and will not receive security updates. Reason given:', 'wordgate' ) . ' ' . ( ! empty( $data['closed_reason'] ) ? $data['closed_reason'] : __( 'unknown', 'wordgate' ) ),
					'',
					array( 'slug' => $slug ),
					'abandoned:' . $slug
				);
			}
		}
		return true;
	}

	private static function phaseIndex( $deadline ) {
		$list     = self::tempFile( 'scan-files.txt' );
		$fp       = fopen( $list, 'w' ); // phpcs:ignore
		$verified = self::verified();
		$exts     = array_flip( array_merge( self::signatures()->extensions(), array( 'php', 'phtml', 'php5', 'php7', 'phar' ) ) );
		$skip     = array( realpath( WORDGATE_DATA_DIR ), realpath( WP_CONTENT_DIR . '/upgrade' ) );
		$roots    = array( ABSPATH );
		if ( 0 !== strpos( realpath( WP_CONTENT_DIR ), realpath( ABSPATH ) ) ) {
			$roots[] = WP_CONTENT_DIR;
		}
		$uploads = wp_get_upload_dir();
		$count   = 0;
		foreach ( $roots as $root ) {
			foreach ( self::walk( $root, $skip ) as $path ) {
				if ( isset( $verified[ $path ] ) ) {
					continue;
				}
				$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				if ( ! isset( $exts[ $ext ] ) ) {
					continue;
				}
				if ( ! Settings::get( 'scan_uploads' ) && 0 === strpos( $path, $uploads['basedir'] ) && ! self::isExecutable( $path ) ) {
					continue;
				}
				fwrite( $fp, $path . "\n" ); // phpcs:ignore
				++$count;
			}
		}
		fclose( $fp ); // phpcs:ignore
		self::$state['stats']['files_total'] = $count;
		return true;
	}

	private static function phaseFiles( $deadline ) {
		$list = self::tempFile( 'scan-files.txt' );
		if ( ! file_exists( $list ) ) {
			return true;
		}
		$fp = fopen( $list, 'r' ); // phpcs:ignore
		fseek( $fp, (int) self::$state['cursor'] );
		$max     = max( 64, (int) Settings::get( 'scan_max_file_kb' ) ) * 1024;
		$uploads = wp_get_upload_dir();
		$sigs    = self::signatures();

		while ( false !== ( $line = fgets( $fp ) ) ) { // phpcs:ignore
			$path = rtrim( $line, "\n" );
			++self::$state['stats']['files_scanned'];

			if ( is_file( $path ) && is_readable( $path ) ) {
				$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				if ( self::isExecutable( $path ) && 0 === strpos( $path, trailingslashit( $uploads['basedir'] ) ) ) {
					self::issue(
						'uploads_php',
						'high',
						/* translators: %s: file */
						sprintf( __( 'PHP file in uploads directory: %s', 'wordgate' ), self::rel( $path ) ),
						__( 'The uploads directory should contain media, not executable code. PHP files here are almost always backdoors uploaded through a vulnerable plugin.', 'wordgate' ),
						$path,
						array( 'repair' => 'delete' )
					);
				}
				$size = filesize( $path );
				if ( $size > 0 && $size <= $max ) {
					$hits = $sigs->scan( (string) file_get_contents( $path ), $ext ); // phpcs:ignore
					foreach ( $hits as $hit ) {
						self::issue(
							'malware',
							$hit['severity'],
							/* translators: 1: file, 2: signature name */
							sprintf( __( 'Possible malware in %1$s: %2$s', 'wordgate' ), self::rel( $path ), $hit['name'] ),
							__( 'This file matches a known malicious code pattern. Review it carefully: if you do not recognise it, delete it or restore a clean copy, then change all passwords.', 'wordgate' ),
							$path,
							array(
								'signature' => $hit['id'],
								'matched'   => $hit['matched'],
								'offset'    => $hit['offset'],
								'repair'    => 'delete',
							),
							$path . '|' . $hit['id']
						);
					}
				}
			}

			if ( microtime( true ) > $deadline ) {
				self::$state['cursor'] = ftell( $fp );
				fclose( $fp ); // phpcs:ignore
				return false;
			}
		}
		fclose( $fp ); // phpcs:ignore
		return true;
	}

	private static function phaseChecks( $deadline ) {
		global $wp_version;

		$freshness = self::refreshUpdateData();
		if ( ! $freshness['ok'] ) {
			self::issue(
				'update_check_failed',
				'medium',
				__( 'WordPress cannot check for plugin and theme updates', 'wordgate' ),
				__( 'Update information is missing or more than two days old, so outdated components may go unreported. Your host may be blocking connections to api.wordpress.org, or WP-Cron may not be running. Visit Dashboard → Updates and click "Check again"; if that fails, contact your host.', 'wordgate' ),
				'',
				$freshness,
				'update_check_failed'
			);
		}

		$core = get_site_transient( 'update_core' );
		if ( isset( $core->updates[0]->response ) && 'upgrade' === $core->updates[0]->response ) {
			self::issue( 'core_update', 'high', sprintf( __( 'WordPress %1$s is available (you have %2$s)', 'wordgate' ), $core->updates[0]->current, $wp_version ), __( 'Core updates frequently include security fixes. Update from Dashboard → Updates.', 'wordgate' ), '', array(), 'core_update' );
		}

		$plugins = get_site_transient( 'update_plugins' );
		if ( ! empty( $plugins->response ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$all = get_plugins();
			foreach ( $plugins->response as $file => $update ) {
				if ( isset( $all[ $file ] ) ) {
					self::issue( 'plugin_update', 'medium', sprintf( __( 'Update available for %1$s (%2$s → %3$s)', 'wordgate' ), $all[ $file ]['Name'], $all[ $file ]['Version'], $update->new_version ), __( 'Outdated plugins are the #1 cause of hacked WordPress sites.', 'wordgate' ), '', array(), 'plugin_update:' . $file . ':' . $update->new_version );
				}
			}
		}

		$themes = get_site_transient( 'update_themes' );
		if ( ! empty( $themes->response ) ) {
			foreach ( $themes->response as $slug => $update ) {
				$theme = wp_get_theme( $slug );
				self::issue( 'theme_update', 'medium', sprintf( __( 'Update available for theme %1$s (%2$s → %3$s)', 'wordgate' ), $theme->get( 'Name' ), $theme->get( 'Version' ), $update['new_version'] ), __( 'Keep themes up to date, including inactive ones.', 'wordgate' ), '', array(), 'theme_update:' . $slug . ':' . $update['new_version'] );
			}
		}

		if ( version_compare( PHP_VERSION, '8.2', '<' ) ) {
			self::issue( 'php_eol', 'medium', sprintf( __( 'PHP %s no longer receives security updates', 'wordgate' ), PHP_VERSION ), __( 'Ask your host to upgrade to a supported PHP version (8.2 or newer).', 'wordgate' ), '', array(), 'php_eol' );
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY !== false && 'production' === wp_get_environment_type() ) {
			self::issue( 'debug_display', 'medium', __( 'Debug output is shown to visitors', 'wordgate' ), __( 'WP_DEBUG_DISPLAY exposes file paths and errors to attackers. Set WP_DEBUG_DISPLAY to false in wp-config.php on live sites.', 'wordgate' ), '', array(), 'debug_display' );
		}

		$log = WP_CONTENT_DIR . '/debug.log';
		if ( file_exists( $log ) && filesize( $log ) > 0 ) {
			self::issue( 'debug_log', 'medium', __( 'debug.log is present in wp-content', 'wordgate' ), __( 'This file is often publicly downloadable and can leak paths, queries and sometimes credentials. Delete it, or point WP_DEBUG_LOG at a path outside the web root.', 'wordgate' ), $log, array( 'repair' => 'delete' ), 'debug_log' );
		}

		$admin = get_user_by( 'login', 'admin' );
		if ( $admin && user_can( $admin, 'manage_options' ) ) {
			self::issue( 'admin_username', 'low', __( 'An administrator uses the username "admin"', 'wordgate' ), __( '"admin" is the first username bots try. Create a new administrator with a unique name and delete this one (attributing content to the new user).', 'wordgate' ), '', array(), 'admin_username' );
		}

		$config = file_exists( ABSPATH . 'wp-config.php' ) ? ABSPATH . 'wp-config.php' : dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $config ) && ( fileperms( $config ) & 0x0004 ) && DIRECTORY_SEPARATOR === '/' ) {
			self::issue( 'config_perms', 'medium', __( 'wp-config.php is world-readable', 'wordgate' ), __( 'Other accounts on the same server may be able to read your database password. Set permissions to 600 or 640.', 'wordgate' ), $config, array(), 'config_perms' );
		}

		if ( ! is_ssl() && 0 !== strpos( home_url(), 'https://' ) ) {
			self::issue( 'no_https', 'medium', __( 'Site is not served over HTTPS', 'wordgate' ), __( 'Passwords and cookies are sent in clear text. Enable HTTPS (free certificates are available from Let\'s Encrypt via most hosts).', 'wordgate' ), '', array(), 'no_https' );
		}

		$roles = (array) Settings::get( 'tfa_required_roles' );
		if ( ! in_array( 'administrator', $roles, true ) ) {
			$without = 0;
			foreach ( get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) ) as $u ) {
				if ( ! \WordGate\Login\TwoFactor::isEnabled( $u->ID ) ) {
					++$without;
				}
			}
			if ( $without ) {
				self::issue( 'admins_no_2fa', 'low', sprintf( _n( '%d administrator has no two-factor authentication', '%d administrators have no two-factor authentication', $without, 'wordgate' ), $without ), __( 'Two-factor authentication stops account takeover even when a password is stolen. Require it for administrators under WordGate → Login Security.', 'wordgate' ), '', array(), 'admins_no_2fa' );
			}
		}
		return true;
	}

	private static function phaseFinish( $deadline ) {
		$resolved = Issues::resolveStale( self::$state['id'] );
		self::cleanupTemp();
		self::$state['status']   = 'done';
		self::$state['finished'] = time();
		$summary                 = array(
			'id'               => self::$state['id'],
			'started'          => self::$state['started'],
			'finished'         => time(),
			'source'           => self::$state['source'],
			'files_scanned'    => self::$state['stats']['files_scanned'],
			'issues'           => self::$state['stats']['issues'],
			'new_issues'       => self::$state['stats']['new_issues'],
			'new_issue_titles' => self::$state['stats']['new_issue_titles'],
			'resolved'         => $resolved,
			'notes'            => self::$state['notes'],
		);
		update_option( self::LAST, $summary, false );
		EventLog::add(
			'scan_finished',
			'',
			array(
				'reason'  => sprintf( '%d issues (%d new), %d files', $summary['issues'], $summary['new_issues'], $summary['files_scanned'] ),
				'details' => array( 'duration' => $summary['finished'] - $summary['started'] ),
			)
		);
		Notifications::scanComplete( $summary );
		return true;
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------- */

	private static function issue( $type, $severity, $title, $description, $file = '', array $data = array(), $subject = null ) {
		$is_new = Issues::report( self::$state['id'], $type, $severity, $title, $description, $file, $data, $subject );
		++self::$state['stats']['issues'];
		if ( $is_new ) {
			++self::$state['stats']['new_issues'];
			if ( count( self::$state['stats']['new_issue_titles'] ) < 50 ) {
				self::$state['stats']['new_issue_titles'][] = $title;
			}
		}
	}

	/**
	 * Make sure WordPress's update data is reasonably fresh before we rely on it.
	 * The scanner used to read the transients as-is and silently reported nothing
	 * when they were missing or stale (issue #35).
	 *
	 * @return array{ok:bool,plugins_checked:int,themes_checked:int}
	 */
	public static function refreshUpdateData() {
		$stale = static function ( $t ) {
			return ! is_object( $t ) || empty( $t->last_checked ) || time() - (int) $t->last_checked > 12 * HOUR_IN_SECONDS;
		};
		if ( ! function_exists( 'wp_update_plugins' ) ) {
			require_once ABSPATH . WPINC . '/update.php';
		}
		if ( $stale( get_site_transient( 'update_plugins' ) ) ) {
			wp_update_plugins();
		}
		if ( $stale( get_site_transient( 'update_themes' ) ) ) {
			wp_update_themes();
		}
		$p   = get_site_transient( 'update_plugins' );
		$t   = get_site_transient( 'update_themes' );
		$pc  = is_object( $p ) && ! empty( $p->last_checked ) ? (int) $p->last_checked : 0;
		$tc  = is_object( $t ) && ! empty( $t->last_checked ) ? (int) $t->last_checked : 0;
		$max = 2 * DAY_IN_SECONDS;
		return array(
			'ok'              => $pc > time() - $max && $tc > time() - $max,
			'plugins_checked' => $pc,
			'themes_checked'  => $tc,
		);
	}

	/**
	 * Latest published version of each wordpress.org plugin/theme, from WordPress's
	 * own update data ("response" = update available, "no_update" = already latest).
	 *
	 * @return array{plugin:array<string,string>,theme:array<string,string>}
	 */
	public static function latestVersions() {
		$out = array(
			'plugin' => array(),
			'theme'  => array(),
		);
		$p = get_site_transient( 'update_plugins' );
		foreach ( array( 'no_update', 'response' ) as $bucket ) {
			if ( is_object( $p ) && ! empty( $p->$bucket ) ) {
				foreach ( (array) $p->$bucket as $file => $info ) {
					$info = (object) $info;
					if ( ! empty( $info->new_version ) ) {
						$out['plugin'][ dirname( $file ) ] = (string) $info->new_version;
					}
				}
			}
		}
		$t = get_site_transient( 'update_themes' );
		foreach ( array( 'no_update', 'response' ) as $bucket ) {
			if ( is_object( $t ) && ! empty( $t->$bucket ) ) {
				foreach ( (array) $t->$bucket as $slug => $info ) {
					$info = (array) $info;
					if ( ! empty( $info['new_version'] ) ) {
						$out['theme'][ $slug ] = (string) $info['new_version'];
					}
				}
			}
		}
		return $out;
	}

	private static function note( $text ) {
		self::$state['notes'][] = $text;
	}

	private static function save() {
		update_option( self::STATE, self::$state, false );
	}

	private static function defaultBudget() {
		$max = (int) ini_get( 'max_execution_time' );
		return $max > 0 ? max( 5, min( 20, $max / 2 ) ) : 20;
	}

	private static function signatures() {
		if ( null === self::$signatures ) {
			$custom           = WORDGATE_DATA_DIR . '/signatures.json';
			self::$signatures = Signatures::fromFile( file_exists( $custom ) ? $custom : WORDGATE_DIR . '/includes/Scanner/signatures.json' );
		}
		return self::$signatures;
	}

	public static function isExecutable( $path ) {
		return (bool) preg_match( '/\.(?:php\d?|phtml|phar|pht|phps)$/i', $path ) || (bool) preg_match( '/\.php\d?\./i', basename( $path ) );
	}

	public static function rel( $path ) {
		return 0 === strpos( $path, ABSPATH ) ? substr( $path, strlen( ABSPATH ) ) : $path;
	}

	/**
	 * Recursively list files, without following symlinked directories.
	 *
	 * @param string[] $skip Real paths of directories to skip.
	 * @return \Generator<string>
	 */
	private static function walk( $dir, array $skip = array() ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$skip = array_filter( $skip );
		$it   = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::UNIX_PATHS ),
				static function ( \SplFileInfo $f ) use ( $skip ) {
					if ( $f->isDir() ) {
						if ( $f->isLink() || in_array( $f->getFilename(), array( '.git', 'node_modules', '.svn' ), true ) ) {
							return false;
						}
						return ! in_array( $f->getRealPath(), $skip, true );
					}
					return true;
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $it as $file ) {
			if ( $file->isFile() ) {
				yield $file->getPathname();
			}
		}
	}

	private static function tempFile( $name ) {
		Plugin::storage()->ensureDir();
		return WORDGATE_DATA_DIR . '/' . $name;
	}

	private static function verified() {
		if ( null === self::$verified ) {
			self::$verified = array();
			$file           = self::tempFile( 'scan-verified.txt' );
			if ( file_exists( $file ) ) {
				foreach ( file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $p ) {
					self::$verified[ $p ] = true;
				}
			}
		}
		return self::$verified;
	}

	private static function addVerified( array $paths ) {
		if ( $paths ) {
			file_put_contents( self::tempFile( 'scan-verified.txt' ), implode( "\n", $paths ) . "\n", FILE_APPEND | LOCK_EX ); // phpcs:ignore
			self::$verified = null;
		}
	}

	private static function cleanupTemp() {
		foreach ( array( 'scan-files.txt', 'scan-verified.txt' ) as $f ) {
			if ( file_exists( WORDGATE_DATA_DIR . '/' . $f ) ) {
				unlink( WORDGATE_DATA_DIR . '/' . $f ); // phpcs:ignore
			}
		}
		self::$verified = null;
	}

	/**
	 * @return array<string,string>|null rel path => md5
	 */
	public static function coreChecksums( $version, $locale ) {
		$key    = 'wordgate_core_sums_' . md5( $version . $locale );
		$cached = get_site_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		foreach ( array_unique( array( $locale, 'en_US' ) ) as $loc ) {
			$res  = wp_remote_get( add_query_arg( array( 'version' => $version, 'locale' => $loc ), 'https://api.wordpress.org/core/checksums/1.0/' ), array( 'timeout' => 20 ) );
			$body = json_decode( wp_remote_retrieve_body( $res ), true );
			if ( ! empty( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
				set_site_transient( $key, $body['checksums'], DAY_IN_SECONDS );
				return $body['checksums'];
			}
		}
		return null;
	}

	/**
	 * @return array|null rel path => ['md5' => string|string[], 'sha256' => ...], or null if unavailable.
	 */
	public static function pluginChecksums( $slug, $version ) {
		$key    = 'wordgate_plugin_sums_' . md5( $slug . $version );
		$cached = get_site_transient( $key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}
		$res  = wp_remote_get( sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $slug ), rawurlencode( $version ) ), array( 'timeout' => 15 ) );
		$code = wp_remote_retrieve_response_code( $res );
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$sums = 200 === $code && ! empty( $body['files'] ) ? $body['files'] : null;
		if ( ! is_wp_error( $res ) ) {
			set_site_transient( $key, null === $sums ? 'none' : $sums, DAY_IN_SECONDS );
		}
		return $sums;
	}
}

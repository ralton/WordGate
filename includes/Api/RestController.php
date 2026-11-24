<?php
/**
 * Read-only REST API for remote diagnostics.
 *
 *   GET  /wp-json/wordgate/v1/status   Firewall, environment, IP detection, settings summary
 *   GET  /wp-json/wordgate/v1/events   Activity log (filters: type, ip, search, since, page, per_page)
 *   GET  /wp-json/wordgate/v1/issues   Scan issues (status=open|ignored|resolved)
 *   GET  /wp-json/wordgate/v1/blocks   Active IP blocks
 *   GET  /wp-json/wordgate/v1/rules    Firewall rules and their state
 *   GET  /wp-json/wordgate/v1/scan     Scan progress / last result
 *   POST /wp-json/wordgate/v1/scan     Start a scan, or continue a running one
 *
 * Access: administrators, or users with the "WordGate Auditor" role — designed to
 * be used with an application password. Nothing here changes settings, content,
 * users or files; the only write is starting a scan (which never repairs).
 *
 * @package WordGate
 */

namespace WordGate\Api;

use WordGate\Firewall\WafConfig;
use WordGate\Firewall\WafInstaller;
use WordGate\Log\EventLog;
use WordGate\Plugin;
use WordGate\Scanner\Issues;
use WordGate\Scanner\ScanRunner;
use WordGate\Settings;

final class RestController {

	const NS       = 'wordgate/v1';
	const CAP_VIEW = 'wordgate_view';
	const CAP_SCAN = 'wordgate_scan';

	public static function register() {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
	}

	public static function routes() {
		$view = array( __CLASS__, 'canView' );
		$get  = \WP_REST_Server::READABLE;

		register_rest_route( self::NS, '/status', array( 'methods' => $get, 'callback' => array( __CLASS__, 'status' ), 'permission_callback' => $view ) );
		register_rest_route(
			self::NS,
			'/events',
			array(
				'methods'             => $get,
				'callback'            => array( __CLASS__, 'events' ),
				'permission_callback' => $view,
				'args'                => array(
					'type'     => array( 'type' => 'string', 'default' => '', 'sanitize_callback' => 'sanitize_key' ),
					'ip'       => array( 'type' => 'string', 'default' => '', 'sanitize_callback' => 'sanitize_text_field' ),
					'search'   => array( 'type' => 'string', 'default' => '', 'sanitize_callback' => 'sanitize_text_field' ),
					'since'    => array( 'type' => 'integer', 'default' => 0, 'minimum' => 0 ),
					'page'     => array( 'type' => 'integer', 'default' => 1, 'minimum' => 1 ),
					'per_page' => array( 'type' => 'integer', 'default' => 100, 'minimum' => 1, 'maximum' => 500 ),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/issues',
			array(
				'methods'             => $get,
				'callback'            => array( __CLASS__, 'issues' ),
				'permission_callback' => $view,
				'args'                => array(
					'status' => array( 'type' => 'string', 'default' => 'open', 'enum' => array( 'open', 'ignored', 'resolved' ) ),
				),
			)
		);
		register_rest_route( self::NS, '/blocks', array( 'methods' => $get, 'callback' => array( __CLASS__, 'blocks' ), 'permission_callback' => $view ) );
		register_rest_route( self::NS, '/rules', array( 'methods' => $get, 'callback' => array( __CLASS__, 'rules' ), 'permission_callback' => $view ) );
		register_rest_route(
			self::NS,
			'/scan',
			array(
				array( 'methods' => $get, 'callback' => array( __CLASS__, 'scanState' ), 'permission_callback' => $view ),
				array( 'methods' => \WP_REST_Server::CREATABLE, 'callback' => array( __CLASS__, 'scanRun' ), 'permission_callback' => array( __CLASS__, 'canScan' ) ),
			)
		);
	}

	public static function canView() {
		return current_user_can( 'manage_options' ) || current_user_can( self::CAP_VIEW );
	}

	public static function canScan() {
		return current_user_can( 'manage_options' ) || current_user_can( self::CAP_SCAN );
	}

	/* ---------------------------------------------------------------------
	 * Endpoints
	 * ------------------------------------------------------------------- */

	public static function status() {
		global $wp_version;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$waf      = WafInstaller::status();
		$settings = Settings::all();
		$blocks   = Plugin::storage()->getBlocks();
		$active   = array_filter(
			$blocks,
			static function ( $b ) {
				return empty( $b['expires'] ) || $b['expires'] > time();
			}
		);

		$plugins = array();
		foreach ( get_plugins() as $file => $p ) {
			$plugins[] = array(
				'file'    => $file,
				'name'    => $p['Name'],
				'version' => $p['Version'],
				'active'  => is_plugin_active( $file ),
			);
		}
		$theme = wp_get_theme();

		return rest_ensure_response(
			array(
				'generated_at' => time(),
				'wordgate'     => array(
					'version'    => WORDGATE_VERSION,
					'db_version' => get_option( 'wordgate_db_version' ),
				),
				'firewall'     => array(
					'mode'              => $settings['waf_mode'],
					'protection'        => $waf['mode'],
					'loaded_this_request' => $waf['loaded'],
					'auto_prepend_file' => $waf['prepend'],
					'prepend_conflict'  => $waf['conflict'],
					'detected_server'   => WafInstaller::detectServer(),
					'stub_exists'       => file_exists( WafInstaller::stubPath() ),
					'mu_loader_exists'  => file_exists( WafInstaller::muPluginPath() ),
					'uploads_php_disabled' => WafInstaller::isUploadsPhpDisabled(),
					'rules_loaded'      => count( WafConfig::rules() ),
					'disabled_rules'    => array_map( 'intval', (array) $settings['disabled_rules'] ),
					'allow_rules'       => array_values( (array) $settings['allow_rules'] ),
					'active_blocks'     => count( $active ),
					'kill_switch'       => file_exists( WORDGATE_DATA_DIR . '/disable-waf' ) || ( defined( 'WORDGATE_WAF_DISABLE' ) && WORDGATE_WAF_DISABLE ),
				),
				'ip_detection' => self::ipDiagnostics(),
				'environment'  => array(
					'php_version'         => PHP_VERSION,
					'php_sapi'            => PHP_SAPI,
					'server_software'     => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '',
					'wp_version'          => $wp_version,
					'multisite'           => is_multisite(),
					'https'               => is_ssl(),
					'environment_type'    => wp_get_environment_type(),
					'apcu'                => function_exists( 'apcu_enabled' ) && apcu_enabled(),
					'opcache'             => function_exists( 'opcache_get_status' ) && (bool) ini_get( 'opcache.enable' ),
					'memory_limit'        => ini_get( 'memory_limit' ),
					'max_execution_time'  => (int) ini_get( 'max_execution_time' ),
					'user_ini_filename'   => ini_get( 'user_ini.filename' ),
					'user_ini_cache_ttl'  => (int) ini_get( 'user_ini.cache_ttl' ),
					'data_dir'            => WORDGATE_DATA_DIR,
					'data_dir_writable'   => is_dir( WORDGATE_DATA_DIR ) && wp_is_writable( WORDGATE_DATA_DIR ),
					'abspath_writable'    => wp_is_writable( ABSPATH ),
					'mu_plugins_writable' => is_dir( WPMU_PLUGIN_DIR ) ? wp_is_writable( WPMU_PLUGIN_DIR ) : wp_is_writable( WP_CONTENT_DIR ),
					'wp_cron_disabled'    => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
					'next_cron'           => array(
						'hourly' => wp_next_scheduled( 'wordgate_hourly' ),
						'daily'  => wp_next_scheduled( 'wordgate_daily' ),
					),
					'active_theme'        => array(
						'name'     => $theme->get( 'Name' ),
						'version'  => $theme->get( 'Version' ),
						'template' => $theme->get_template(),
					),
					'plugins'             => $plugins,
					'mu_plugins'          => array_values(
						array_map(
							static function ( $p ) {
								return $p['Name'] . ( $p['Version'] ? ' ' . $p['Version'] : '' );
							},
							get_mu_plugins()
						)
					),
					'dropins'             => array_keys( get_dropins() ),
				),
				'updates'      => self::updateDiagnostics(),
				'settings'     => self::publicSettings( $settings ),
				'scan'         => array(
					'state'  => ScanRunner::publicState( ScanRunner::state() ),
					'last'   => get_option( ScanRunner::LAST ) ?: null,
					'counts' => Issues::counts(),
				),
			)
		);
	}

	public static function events( \WP_REST_Request $req ) {
		EventLog::ingest();
		$result = EventLog::query(
			array(
				'type'     => $req['type'],
				'ip'       => $req['ip'],
				'search'   => $req['search'],
				'since'    => $req['since'],
				'page'     => $req['page'],
				'per_page' => $req['per_page'],
			)
		);
		$rows = array_map(
			static function ( $r ) {
				$r['id']      = (int) $r['id'];
				$r['created'] = (int) $r['created'];
				$r['rule_id'] = (int) $r['rule_id'];
				$r['details'] = '' !== $r['details'] ? json_decode( $r['details'], true ) : null;
				return $r;
			},
			$result['rows']
		);
		$response = rest_ensure_response( $rows );
		$response->header( 'X-WP-Total', (string) $result['total'] );
		$response->header( 'X-WP-TotalPages', (string) (int) ceil( $result['total'] / max( 1, (int) $req['per_page'] ) ) );
		return $response;
	}

	public static function issues( \WP_REST_Request $req ) {
		$rows = array_map(
			static function ( $i ) {
				$i['file'] = '' !== $i['file'] ? ScanRunner::rel( $i['file'] ) : '';
				$i['data'] = (object) $i['data']; // Always a JSON object, never [].
				unset( $i['hash'] );
				return $i;
			},
			Issues::all( $req['status'] )
		);
		return rest_ensure_response( $rows );
	}

	public static function blocks() {
		$out = array();
		foreach ( Plugin::storage()->getBlocks() as $range => $b ) {
			$out[] = array( 'range' => (string) $range ) + $b + array( 'expired' => ! empty( $b['expires'] ) && $b['expires'] < time() );
		}
		return rest_ensure_response( $out );
	}

	public static function rules() {
		$disabled = array_map( 'intval', (array) Settings::get( 'disabled_rules' ) );
		$out      = array();
		foreach ( WafConfig::rules() as $r ) {
			$out[] = array(
				'id'           => $r->id,
				'name'         => $r->name,
				'category'     => $r->category,
				'severity'     => $r->severity,
				'action'       => $r->action,
				'targets'      => $r->targets,
				'admin_bypass' => $r->adminBypass,
				'enabled'      => ! in_array( $r->id, $disabled, true ),
			);
		}
		return rest_ensure_response( $out );
	}

	public static function scanState() {
		return rest_ensure_response(
			array(
				'state' => ScanRunner::publicState( ScanRunner::state() ),
				'last'  => get_option( ScanRunner::LAST ) ?: null,
			)
		);
	}

	/**
	 * Start a scan if none is running, then work on it for a few seconds.
	 * Call repeatedly until state.status is "done".
	 */
	public static function scanRun() {
		if ( ! ScanRunner::isRunning() ) {
			ScanRunner::start( 'api' );
		}
		return rest_ensure_response( array( 'state' => ScanRunner::publicState( ScanRunner::step( 15 ) ) ) );
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------- */

	/**
	 * Everything needed to debug IP detection: what WordGate resolved, the raw
	 * peer address, and any forwarding headers present on this request.
	 */
	private static function ipDiagnostics() {
		$headers = array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED', 'HTTP_X_SUCURI_CLIENTIP', 'HTTP_FASTLY_CLIENT_IP' );
		$present = array();
		foreach ( $headers as $h ) {
			if ( ! empty( $_SERVER[ $h ] ) ) {
				$present[ $h ] = sanitize_text_field( wp_unslash( $_SERVER[ $h ] ) );
			}
		}
		return array(
			'resolved_client_ip' => Plugin::clientIp(),
			'remote_addr'        => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
			'ip_source_setting'  => Settings::get( 'ip_source' ),
			'trusted_proxies'    => Settings::lines( 'trusted_proxies' ),
			'forwarding_headers' => $present,
		);
	}

	/**
	 * What WordPress currently knows about available updates (issue #35).
	 */
	private static function updateDiagnostics() {
		$out = array();
		foreach ( array( 'core' => 'update_core', 'plugins' => 'update_plugins', 'themes' => 'update_themes' ) as $k => $transient ) {
			$t = get_site_transient( $transient );
			if ( ! is_object( $t ) ) {
				$out[ $k ] = array( 'present' => false );
				continue;
			}
			$row = array(
				'present'      => true,
				'last_checked' => isset( $t->last_checked ) ? (int) $t->last_checked : 0,
			);
			if ( 'core' === $k ) {
				$row['offer'] = isset( $t->updates[0]->response ) ? $t->updates[0]->response . ' ' . $t->updates[0]->current : '';
			} else {
				$row['updates_available'] = array();
				foreach ( isset( $t->response ) ? (array) $t->response : array() as $key => $info ) {
					$info                       = (array) $info;
					$row['updates_available'][] = $key . ' → ' . ( isset( $info['new_version'] ) ? $info['new_version'] : '?' );
				}
				$row['up_to_date_count'] = isset( $t->no_update ) ? count( (array) $t->no_update ) : 0;
				if ( isset( $t->translations ) ) {
					$row['translations'] = count( (array) $t->translations );
				}
			}
			$out[ $k ] = $row;
		}
		$out['auto_updater_disabled'] = defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED;
		$out['filters']               = array(
			'pre_site_transient_update_plugins' => has_filter( 'pre_site_transient_update_plugins' ) ? true : false,
			'site_transient_update_plugins'     => has_filter( 'site_transient_update_plugins' ) ? true : false,
		);
		return $out;
	}

	/**
	 * Settings minus anything personal. (WordGate stores no secrets in settings;
	 * the WAF signing secret lives in its own option and is never exposed.)
	 */
	private static function publicSettings( array $settings ) {
		unset( $settings['notify_email'] );
		$settings['notify_email_set'] = '' !== (string) Settings::get( 'notify_email' );
		return $settings;
	}
}

<?php
/**
 * File-based storage shared by the pre-WordPress WAF and the WordPress plugin.
 *
 * Everything lives under one data directory (default wp-content/wordgate/):
 *
 *   config.php        WAF configuration, written by the plugin (PHP array, opcache-friendly)
 *   blocks.php        Active IP blocks
 *   rules.php         Compiled rule cache
 *   attack-log.jsonl  Append-only log of WAF events, ingested by the plugin into the DB
 *   counters/         Rate-limit counters (only if APCu is unavailable)
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Storage {

	/** @var string */
	private $dir;

	/** @var array|null */
	private $blocksCache;

	public function __construct( $dir ) {
		$this->dir = rtrim( (string) $dir, '/\\' );
	}

	public function dir() {
		return $this->dir;
	}

	/**
	 * Create the data directory and lock it down against direct web access.
	 */
	public function ensureDir() {
		if ( ! is_dir( $this->dir ) && ! @mkdir( $this->dir, 0750, true ) ) { // phpcs:ignore
			return false;
		}
		$guards = array(
			'index.php'  => "<?php\n// Silence is golden.\n",
			'.htaccess'  => "# Apache 2.4\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n# Apache 2.2\n<IfModule !mod_authz_core.c>\n\tOrder deny,allow\n\tDeny from all\n</IfModule>\n",
			'web.config' => "<?xml version=\"1.0\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);
		foreach ( $guards as $name => $content ) {
			$path = $this->dir . '/' . $name;
			if ( ! file_exists( $path ) ) {
				@file_put_contents( $path, $content ); // phpcs:ignore
			}
		}
		return is_writable( $this->dir );
	}

	/* ---------------------------------------------------------------------
	 * Config
	 * ------------------------------------------------------------------- */

	public function readConfig() {
		$config = $this->readPhp( 'config.php' );
		return array_replace_recursive( self::defaultConfig(), $config );
	}

	public function writeConfig( array $config ) {
		return $this->writePhp( 'config.php', $config );
	}

	public static function defaultConfig() {
		return array(
			'mode'            => 'enabled', // enabled | learning | disabled
			'ip_source'       => 'REMOTE_ADDR',
			'trusted_proxies' => array(),
			'allowlist_ips'   => array(),
			'disabled_rules'  => array(),
			'allow_rules'     => array(), // [ ['rule_id'=>int|0, 'path'=>regex|'', 'param'=>string|''] ]
			'rate_limit'      => array(
				'enabled'             => false,
				'requests_per_minute' => 240,
				'action'              => 'throttle', // throttle | block
				'block_minutes'       => 30,
			),
			'block_page'      => array(
				'show_reason' => false,
			),
			'auth_secret'     => '',
		);
	}

	/* ---------------------------------------------------------------------
	 * IP blocks
	 * ------------------------------------------------------------------- */

	/**
	 * @return array<string,array{reason:string,expires:int,created:int,scope:string,source:string}>
	 */
	public function getBlocks() {
		if ( null === $this->blocksCache ) {
			$this->blocksCache = $this->readPhp( 'blocks.php' );
		}
		return $this->blocksCache;
	}

	/**
	 * Find an active block matching an IP. Expired entries are ignored.
	 *
	 * @param string $scope 'all' or 'login'. A login request also matches 'all' blocks.
	 * @return array|null
	 */
	public function findBlock( $ip, $isLoginRequest = false ) {
		$now = time();
		foreach ( $this->getBlocks() as $range => $block ) {
			if ( ! empty( $block['expires'] ) && $block['expires'] < $now ) {
				continue;
			}
			$scope = isset( $block['scope'] ) ? $block['scope'] : 'all';
			if ( 'login' === $scope && ! $isLoginRequest ) {
				continue;
			}
			if ( IpUtil::inRange( $ip, (string) $range ) ) {
				return array( 'range' => (string) $range ) + $block;
			}
		}
		return null;
	}

	/**
	 * Add or replace a block.
	 *
	 * @param int    $minutes 0 = permanent.
	 * @param string $scope   'all' (entire site) or 'login' (wp-login.php / xmlrpc.php only).
	 */
	public function addBlock( $range, $reason, $minutes = 0, $scope = 'all', $source = 'manual' ) {
		if ( ! IpUtil::isValidRange( $range ) ) {
			return false;
		}
		if ( false === strpos( $range, '/' ) ) {
			$range = IpUtil::normalize( $range );
		}
		return $this->mutateBlocks(
			function ( array $blocks ) use ( $range, $reason, $minutes, $scope, $source ) {
				$blocks[ $range ] = array(
					'reason'  => (string) $reason,
					'created' => time(),
					'expires' => $minutes > 0 ? time() + (int) $minutes * 60 : 0,
					'scope'   => 'login' === $scope ? 'login' : 'all',
					'source'  => (string) $source,
				);
				return $blocks;
			}
		);
	}

	public function removeBlock( $range ) {
		if ( false === strpos( $range, '/' ) && IpUtil::isValid( $range ) ) {
			$range = IpUtil::normalize( $range );
		}
		return $this->mutateBlocks(
			function ( array $blocks ) use ( $range ) {
				unset( $blocks[ $range ] );
				return $blocks;
			}
		);
	}

	/**
	 * Drop expired blocks. Returns number removed.
	 */
	public function purgeExpiredBlocks() {
		$removed = 0;
		$this->mutateBlocks(
			function ( array $blocks ) use ( &$removed ) {
				$now = time();
				foreach ( $blocks as $k => $b ) {
					if ( ! empty( $b['expires'] ) && $b['expires'] < $now ) {
						unset( $blocks[ $k ] );
						++$removed;
					}
				}
				return $blocks;
			}
		);
		return $removed;
	}

	private function mutateBlocks( callable $fn ) {
		$lock = $this->lock( 'blocks' );
		$this->blocksCache = null;
		$blocks            = $fn( $this->readPhp( 'blocks.php', true ) );
		$ok                = $this->writePhp( 'blocks.php', $blocks );
		$this->blocksCache = $blocks;
		$this->unlock( $lock );
		return $ok;
	}

	/* ---------------------------------------------------------------------
	 * Counters (rate limiting, brute force)
	 * ------------------------------------------------------------------- */

	/**
	 * Increment a fixed-window counter and return its new value.
	 *
	 * @param string $key    Counter name, e.g. "req:1.2.3.4".
	 * @param int    $window Window length in seconds.
	 */
	public function increment( $key, $window ) {
		$window = max( 1, (int) $window );
		if ( function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			$k = 'wordgate:' . $key;
			apcu_add( $k, 0, $window );
			$v = apcu_inc( $k );
			return false === $v ? 1 : (int) $v;
		}

		$dir = $this->dir . '/counters';
		if ( ! is_dir( $dir ) ) {
			@mkdir( $dir, 0750, true ); // phpcs:ignore
		}
		$file = $dir . '/' . sha1( $key ) . '.cnt';
		$fp   = @fopen( $file, 'c+' ); // phpcs:ignore
		if ( ! $fp ) {
			return 0;
		}
		flock( $fp, LOCK_EX );
		$raw   = stream_get_contents( $fp );
		$now   = time();
		$state = $raw ? explode( ':', $raw ) : array( $now, 0 );
		$start = (int) $state[0];
		$count = isset( $state[1] ) ? (int) $state[1] : 0;
		if ( $now - $start >= $window ) {
			$start = $now;
			$count = 0;
		}
		++$count;
		ftruncate( $fp, 0 );
		rewind( $fp );
		fwrite( $fp, $start . ':' . $count ); // phpcs:ignore
		fflush( $fp );
		flock( $fp, LOCK_UN );
		fclose( $fp ); // phpcs:ignore
		return $count;
	}

	public function resetCounter( $key ) {
		if ( function_exists( 'apcu_enabled' ) && apcu_enabled() ) {
			apcu_delete( 'wordgate:' . $key );
		}
		$file = $this->dir . '/counters/' . sha1( $key ) . '.cnt';
		if ( file_exists( $file ) ) {
			@unlink( $file ); // phpcs:ignore
		}
	}

	/**
	 * Remove counter files older than $maxAge seconds.
	 */
	public function purgeCounters( $maxAge = 86400 ) {
		$dir = $this->dir . '/counters';
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) glob( $dir . '/*.cnt' ) as $f ) {
			if ( is_string( $f ) && filemtime( $f ) < time() - $maxAge ) {
				@unlink( $f ); // phpcs:ignore
			}
		}
	}

	/* ---------------------------------------------------------------------
	 * Attack log
	 * ------------------------------------------------------------------- */

	public function appendLog( array $record ) {
		$file = $this->dir . '/attack-log.jsonl';
		// Hard cap at 20 MB so an attack flood cannot fill the disk before ingestion.
		if ( file_exists( $file ) && filesize( $file ) > 20 * 1024 * 1024 ) {
			return false;
		}
		return false !== @file_put_contents( $file, json_encode( $record, JSON_UNESCAPED_SLASHES ) . "\n", FILE_APPEND | LOCK_EX ); // phpcs:ignore
	}

	/**
	 * Atomically take all pending log records.
	 *
	 * @return array[]
	 */
	public function drainLog( $max = 5000 ) {
		$file = $this->dir . '/attack-log.jsonl';
		if ( ! file_exists( $file ) || 0 === filesize( $file ) ) {
			return array();
		}
		$tmp = $this->dir . '/attack-log.' . getmypid() . '.' . mt_rand() . '.processing';
		if ( ! @rename( $file, $tmp ) ) { // phpcs:ignore
			return array();
		}
		$records = array();
		$fp      = fopen( $tmp, 'r' ); // phpcs:ignore
		while ( $fp && false !== ( $line = fgets( $fp ) ) && count( $records ) < $max ) { // phpcs:ignore
			$rec = json_decode( $line, true );
			if ( is_array( $rec ) ) {
				$records[] = $rec;
			}
		}
		if ( $fp ) {
			fclose( $fp ); // phpcs:ignore
		}
		@unlink( $tmp ); // phpcs:ignore
		return $records;
	}

	/* ---------------------------------------------------------------------
	 * Rules
	 * ------------------------------------------------------------------- */

	/**
	 * Load rules, preferring a downloaded rules.json in the data dir over the
	 * bundled file. The parsed result is cached as PHP for opcache.
	 *
	 * @return Rule[]
	 */
	public function loadRules( $bundledFile ) {
		$source = file_exists( $this->dir . '/rules.json' ) ? $this->dir . '/rules.json' : $bundledFile;
		$cache  = $this->dir . '/rules.php';
		$defs   = null;

		if ( file_exists( $cache ) && file_exists( $source ) && filemtime( $cache ) >= filemtime( $source ) ) {
			$cached = $this->readPhp( 'rules.php' );
			if ( isset( $cached['source'] ) && $cached['source'] === $source ) {
				$defs = $cached['rules'];
			}
		}
		if ( null === $defs ) {
			$json = file_exists( $source ) ? json_decode( (string) file_get_contents( $source ), true ) : null; // phpcs:ignore
			$defs = is_array( $json ) && isset( $json['rules'] ) ? $json['rules'] : array();
			if ( is_dir( $this->dir ) && is_writable( $this->dir ) ) {
				$this->writePhp(
					'rules.php',
					array(
						'source' => $source,
						'rules'  => $defs,
					)
				);
			}
		}

		$rules = array();
		foreach ( $defs as $def ) {
			if ( isset( $def['id'], $def['name'], $def['pattern'] ) ) {
				$rules[] = new Rule( $def );
			}
		}
		return $rules;
	}

	/* ---------------------------------------------------------------------
	 * Low-level helpers
	 * ------------------------------------------------------------------- */

	private function readPhp( $name, $bypassOpcache = false ) {
		$path = $this->dir . '/' . $name;
		if ( ! file_exists( $path ) ) {
			return array();
		}
		if ( $bypassOpcache && function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore
		}
		$data = include $path;
		return is_array( $data ) ? $data : array();
	}

	/**
	 * Write atomically (temp file + rename) so readers never see a half-written file.
	 */
	private function writePhp( $name, array $data ) {
		if ( ! is_dir( $this->dir ) && ! $this->ensureDir() ) {
			return false;
		}
		$path    = $this->dir . '/' . $name;
		$tmp     = $path . '.' . getmypid() . '.' . mt_rand() . '.tmp';
		$content = "<?php\n// Generated by WordGate. Do not edit.\nif ( ! defined( 'WORDGATE_DATA_DIR' ) && ! defined( 'ABSPATH' ) ) { exit; }\nreturn " . var_export( $data, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		if ( false === @file_put_contents( $tmp, $content, LOCK_EX ) ) { // phpcs:ignore
			return false;
		}
		@chmod( $tmp, 0640 ); // phpcs:ignore
		if ( ! @rename( $tmp, $path ) ) { // phpcs:ignore
			@unlink( $tmp ); // phpcs:ignore
			return false;
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore
		}
		return true;
	}

	private function lock( $name ) {
		if ( ! is_dir( $this->dir ) ) {
			$this->ensureDir();
		}
		$fp = @fopen( $this->dir . '/.' . $name . '.lock', 'c' ); // phpcs:ignore
		if ( $fp ) {
			flock( $fp, LOCK_EX );
		}
		return $fp;
	}

	private function unlock( $fp ) {
		if ( $fp ) {
			flock( $fp, LOCK_UN );
			fclose( $fp ); // phpcs:ignore
		}
	}
}

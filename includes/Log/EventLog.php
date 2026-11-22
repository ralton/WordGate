<?php
/**
 * Security event log (database table) and WAF log ingestion.
 *
 * @package WordGate
 */

namespace WordGate\Log;

use WordGate\Plugin;
use WordGate\Settings;

final class EventLog {

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'wordgate_events';
	}

	public static function register() {
		add_action( 'wordgate_hourly', array( __CLASS__, 'ingest' ) );
		add_action( 'wordgate_daily', array( __CLASS__, 'prune' ) );
	}

	/**
	 * Record an event.
	 *
	 * @param string $type     login_failed | lockout | waf_block | 2fa_failed | ...
	 * @param string $ip       Client IP.
	 * @param array  $data     Optional: user_login, uri, method, rule_id, reason, details (array).
	 * @param string $severity info | low | medium | high | critical.
	 */
	public static function add( $type, $ip, array $data = array(), $severity = 'info', $time = null ) {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'created'    => null === $time ? time() : (int) $time,
				'type'       => substr( (string) $type, 0, 32 ),
				'severity'   => substr( (string) $severity, 0, 16 ),
				'ip'         => substr( (string) $ip, 0, 45 ),
				'user_login' => isset( $data['user_login'] ) ? substr( (string) $data['user_login'], 0, 60 ) : '',
				'method'     => isset( $data['method'] ) ? substr( (string) $data['method'], 0, 10 ) : '',
				'uri'        => isset( $data['uri'] ) ? substr( (string) $data['uri'], 0, 2048 ) : '',
				'rule_id'    => isset( $data['rule_id'] ) ? (int) $data['rule_id'] : 0,
				'reason'     => isset( $data['reason'] ) ? substr( (string) $data['reason'], 0, 255 ) : '',
				'details'    => isset( $data['details'] ) ? wp_json_encode( $data['details'] ) : '',
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	/**
	 * Move WAF events from the data directory into the database.
	 */
	public static function ingest() {
		$map = array(
			'rule_block' => 'waf_block',
			'ip_block'   => 'ip_blocked',
			'rate_limit' => 'rate_limit',
			'learning'   => 'waf_learning',
			'rule_log'   => 'waf_log',
		);
		$n   = 0;
		foreach ( Plugin::storage()->drainLog() as $r ) {
			$type = isset( $map[ $r['type'] ] ) ? $map[ $r['type'] ] : 'waf_' . $r['type'];
			self::add(
				$type,
				isset( $r['ip'] ) ? $r['ip'] : '',
				array(
					'method'  => isset( $r['method'] ) ? $r['method'] : '',
					'uri'     => isset( $r['uri'] ) ? $r['uri'] : '',
					'rule_id' => isset( $r['rule_id'] ) ? $r['rule_id'] : 0,
					'reason'  => isset( $r['reason'] ) ? $r['reason'] : '',
					'details' => array(
						'ua'       => isset( $r['ua'] ) ? $r['ua'] : '',
						'match'    => isset( $r['match'] ) ? $r['match'] : null,
						'category' => isset( $r['category'] ) ? $r['category'] : '',
						'status'   => isset( $r['status'] ) ? $r['status'] : 0,
					),
				),
				! empty( $r['severity'] ) ? $r['severity'] : 'medium',
				isset( $r['time'] ) ? $r['time'] : null
			);
			++$n;
		}
		return $n;
	}

	public static function prune() {
		global $wpdb;
		$days = max( 1, (int) Settings::get( 'log_retention_days' ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE created < %d', time() - $days * DAY_IN_SECONDS ) ); // phpcs:ignore
		Plugin::storage()->purgeExpiredBlocks();
		Plugin::storage()->purgeCounters();
	}

	/**
	 * Query events for the admin UI.
	 *
	 * @param array $args type, ip, search, per_page, page.
	 * @return array{rows:array,total:int}
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$args  = wp_parse_args(
			$args,
			array(
				'type'     => '',
				'ip'       => '',
				'search'   => '',
				'since'    => 0,
				'per_page' => 50,
				'page'     => 1,
			)
		);
		$where = array( '1=1' );
		$vals  = array();
		if ( '' !== $args['type'] ) {
			$where[] = 'type = %s';
			$vals[]  = $args['type'];
		}
		if ( '' !== $args['ip'] ) {
			$where[] = 'ip = %s';
			$vals[]  = $args['ip'];
		}
		if ( (int) $args['since'] > 0 ) {
			$where[] = 'created >= %d';
			$vals[]  = (int) $args['since'];
		}
		if ( '' !== $args['search'] ) {
			$like    = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[] = '(uri LIKE %s OR reason LIKE %s OR user_login LIKE %s)';
			array_push( $vals, $like, $like, $like );
		}
		$sql_where = implode( ' AND ', $where );
		$limit     = max( 1, (int) $args['per_page'] );
		$offset    = ( max( 1, (int) $args['page'] ) - 1 ) * $limit;
		$table     = self::table();

		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$sql_where}";
		$rows_sql  = "SELECT * FROM {$table} WHERE {$sql_where} ORDER BY id DESC LIMIT {$limit} OFFSET {$offset}";
		$total     = (int) ( $vals ? $wpdb->get_var( $wpdb->prepare( $count_sql, $vals ) ) : $wpdb->get_var( $count_sql ) );
		$rows      = $vals ? $wpdb->get_results( $wpdb->prepare( $rows_sql, $vals ), ARRAY_A ) : $wpdb->get_results( $rows_sql, ARRAY_A );
		// phpcs:enable
		return array(
			'rows'  => $rows ? $rows : array(),
			'total' => $total,
		);
	}

	/**
	 * Aggregates for the dashboard.
	 */
	public static function stats( $since ) {
		global $wpdb;
		$t = self::table();
		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$by_type  = $wpdb->get_results( $wpdb->prepare( "SELECT type, COUNT(*) AS n FROM {$t} WHERE created >= %d GROUP BY type", $since ), ARRAY_A );
		$top_ips  = $wpdb->get_results( $wpdb->prepare( "SELECT ip, COUNT(*) AS n FROM {$t} WHERE created >= %d AND type IN ('waf_block','ip_blocked','login_failed','lockout','rate_limit') GROUP BY ip ORDER BY n DESC LIMIT 10", $since ), ARRAY_A );
		$top_rule = $wpdb->get_results( $wpdb->prepare( "SELECT rule_id, reason, COUNT(*) AS n FROM {$t} WHERE created >= %d AND type = 'waf_block' GROUP BY rule_id, reason ORDER BY n DESC LIMIT 10", $since ), ARRAY_A );
		$daily    = $wpdb->get_results( $wpdb->prepare( "SELECT FLOOR(created/86400) AS d, COUNT(*) AS n FROM {$t} WHERE created >= %d AND type IN ('waf_block','ip_blocked','rate_limit','lockout') GROUP BY d ORDER BY d", $since ), ARRAY_A );
		// phpcs:enable
		return array(
			'by_type'   => wp_list_pluck( $by_type, 'n', 'type' ),
			'top_ips'   => $top_ips,
			'top_rules' => $top_rule,
			'daily'     => wp_list_pluck( $daily, 'n', 'd' ),
		);
	}
}

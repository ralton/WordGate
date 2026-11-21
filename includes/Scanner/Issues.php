<?php
/**
 * Scan findings persisted in {prefix}wordgate_issues.
 *
 * Each issue has a stable hash (type + subject) so re-scans update the same
 * row, ignored issues stay ignored, and issues that disappear are resolved.
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class Issues {

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'wordgate_issues';
	}

	/**
	 * Insert or refresh an issue. Returns true if it is new.
	 */
	public static function report( $scan_id, $type, $severity, $title, $description, $file = '', array $data = array(), $subject = null ) {
		global $wpdb;
		$hash = sha1( $type . '|' . ( null === $subject ? $file . '|' . $title : $subject ) );
		$t    = self::table();
		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$row  = $wpdb->get_row( $wpdb->prepare( "SELECT id, status FROM {$t} WHERE hash = %s", $hash ), ARRAY_A );
		$now  = time();
		$vals = array(
			'type'        => $type,
			'severity'    => $severity,
			'title'       => substr( $title, 0, 255 ),
			'description' => $description,
			'file'        => substr( $file, 0, 1024 ),
			'data'        => wp_json_encode( $data ),
			'last_seen'   => $now,
			'scan_id'     => (int) $scan_id,
		);
		if ( $row ) {
			if ( 'resolved' === $row['status'] ) {
				$vals['status'] = 'open';
			}
			$wpdb->update( $t, $vals, array( 'id' => $row['id'] ) );
			return 'resolved' === $row['status'];
		}
		$wpdb->insert(
			$t,
			$vals + array(
				'hash'       => $hash,
				'status'     => 'open',
				'first_seen' => $now,
			)
		);
		// phpcs:enable
		return true;
	}

	/**
	 * Mark open issues not seen in this scan as resolved.
	 */
	public static function resolveStale( $scan_id ) {
		global $wpdb;
		$t = self::table();
		return (int) $wpdb->query( $wpdb->prepare( "UPDATE {$t} SET status = 'resolved' WHERE status = 'open' AND scan_id <> %d", $scan_id ) ); // phpcs:ignore
	}

	public static function setStatus( $id, $status ) {
		global $wpdb;
		if ( ! in_array( $status, array( 'open', 'ignored', 'resolved' ), true ) ) {
			return false;
		}
		return false !== $wpdb->update( self::table(), array( 'status' => $status ), array( 'id' => (int) $id ) ); // phpcs:ignore
	}

	public static function get( $id ) {
		global $wpdb;
		$t   = self::table();
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$t} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore
		if ( $row ) {
			$row['data'] = json_decode( $row['data'], true );
		}
		return $row;
	}

	/**
	 * @return array[]
	 */
	public static function all( $status = 'open' ) {
		global $wpdb;
		$t     = self::table();
		$order = "FIELD(severity,'critical','high','medium','low','info'), id DESC";
		// phpcs:disable WordPress.DB.PreparedSQL, WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$t} WHERE status = %s ORDER BY {$order} LIMIT 1000", $status ), ARRAY_A );
		// phpcs:enable
		$rows = is_array( $rows ) ? $rows : array();
		foreach ( $rows as $k => $r ) {
			$rows[ $k ]['data'] = (array) json_decode( $r['data'], true );
		}
		return $rows;
	}

	public static function counts() {
		global $wpdb;
		$t    = self::table();
		$rows = $wpdb->get_results( "SELECT status, severity, COUNT(*) AS n FROM {$t} GROUP BY status, severity", ARRAY_A ); // phpcs:ignore
		$out  = array(
			'open'     => 0,
			'ignored'  => 0,
			'resolved' => 0,
			'critical' => 0,
			'high'     => 0,
		);
		foreach ( (array) $rows as $r ) {
			$out[ $r['status'] ] = ( isset( $out[ $r['status'] ] ) ? $out[ $r['status'] ] : 0 ) + (int) $r['n'];
			if ( 'open' === $r['status'] && isset( $out[ $r['severity'] ] ) ) {
				$out[ $r['severity'] ] += (int) $r['n'];
			}
		}
		return $out;
	}
}

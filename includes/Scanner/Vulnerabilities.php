<?php
/**
 * Known-vulnerability lookups against the open WPVulnerability database
 * (https://www.wpvulnerability.net/). Only the component slug is sent — never
 * your site URL. Disable under Settings → Scanner if you prefer.
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class Vulnerabilities {

	const API = 'https://www.wpvulnerability.net/';

	/**
	 * @param string $kind plugin | theme.
	 * @return array|null The API "data" object.
	 */
	public static function lookup( $kind, $slug ) {
		$key    = 'wordgate_vuln_' . md5( $kind . $slug );
		$cached = get_site_transient( $key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}
		$res = wp_remote_get( self::API . $kind . '/' . rawurlencode( $slug ) . '/', array( 'timeout' => 10 ) );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		$data = isset( $body['data'] ) && is_array( $body['data'] ) ? $body['data'] : null;
		set_site_transient( $key, null === $data ? 'none' : $data, 12 * HOUR_IN_SECONDS );
		return $data;
	}

	/**
	 * Vulnerabilities that affect a specific installed version.
	 *
	 * @return array[] id, title, severity, fixed_in, references
	 */
	public static function affecting( array $data, $version ) {
		$out = array();
		foreach ( isset( $data['vulnerability'] ) ? (array) $data['vulnerability'] : array() as $v ) {
			$op = isset( $v['operator'] ) ? $v['operator'] : array();
			if ( ! self::versionMatches( $version, $op ) ) {
				continue;
			}
			$refs = array();
			foreach ( isset( $v['source'] ) ? (array) $v['source'] : array() as $s ) {
				if ( ! empty( $s['link'] ) ) {
					$refs[] = array(
						'id'   => isset( $s['id'] ) ? $s['id'] : '',
						'name' => isset( $s['name'] ) ? wp_strip_all_tags( html_entity_decode( $s['name'] ) ) : '',
						'url'  => esc_url_raw( $s['link'] ),
					);
				}
			}
			$fixed = ( ! empty( $op['max_version'] ) && isset( $op['max_operator'] ) && 'lt' === $op['max_operator'] && empty( $op['unfixed'] ) ) ? $op['max_version'] : '';
			$out[] = array(
				'id'         => isset( $v['uuid'] ) ? $v['uuid'] : md5( wp_json_encode( $v ) ),
				'title'      => self::title( $v, $refs ),
				'severity'   => self::severity( $v ),
				'fixed_in'   => $fixed,
				'references' => array_slice( $refs, 0, 5 ),
			);
		}
		return $out;
	}

	public static function versionMatches( $version, array $op ) {
		if ( '' === (string) $version ) {
			return false;
		}
		if ( ! empty( $op['min_version'] ) ) {
			$cmp = isset( $op['min_operator'] ) && 'gt' === $op['min_operator'] ? '>' : '>=';
			if ( ! version_compare( $version, $op['min_version'], $cmp ) ) {
				return false;
			}
		}
		if ( ! empty( $op['max_version'] ) ) {
			$cmp = isset( $op['max_operator'] ) && 'le' === $op['max_operator'] ? '<=' : '<';
			if ( ! version_compare( $version, $op['max_version'], $cmp ) ) {
				return false;
			}
		}
		return ! empty( $op['min_version'] ) || ! empty( $op['max_version'] ) || ! empty( $op['unfixed'] );
	}

	private static function title( array $v, array $refs ) {
		// Prefer a descriptive source title ("... - Arbitrary File Upload") over the bare "Name < x.y" form.
		foreach ( $refs as $r ) {
			if ( false !== strpos( $r['name'], ' - ' ) ) {
				return substr( $r['name'], strpos( $r['name'], ' - ' ) + 3 );
			}
		}
		return isset( $v['name'] ) ? wp_strip_all_tags( $v['name'] ) : __( 'Known vulnerability', 'wordgate' );
	}

	private static function severity( array $v ) {
		$impact = isset( $v['impact'] ) ? $v['impact'] : array();
		if ( ! empty( $impact['ssvc']['kev'] ) ) {
			return 'critical'; // Listed in CISA's Known Exploited Vulnerabilities catalog.
		}
		$score = isset( $impact['cvss']['score'] ) ? (float) $impact['cvss']['score'] : null;
		if ( null !== $score ) {
			if ( $score >= 9 ) {
				return 'critical';
			}
			if ( $score >= 7 ) {
				return 'high';
			}
			return $score >= 4 ? 'medium' : 'low';
		}
		return 'high';
	}
}

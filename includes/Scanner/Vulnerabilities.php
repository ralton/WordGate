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

	const SEVERITY_ORDER = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
	);

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
	 * One summary per component, so a plugin with 16 CVEs is one issue, not 16.
	 *
	 * @param string $latest Latest published version, if known.
	 * @return array|null null when the installed version is not affected. Otherwise:
	 *   count, severity (highest), fixed_in (recommended target, may be ''), newer_than
	 *   (set when the only guidance is "a release newer than X"), unfixed (bool: some have no
	 *   fix at all), items (each: id, title, severity, rated, fixed_in, fixed_after, unfixed,
	 *   references), sorted most severe first.
	 */
	public static function summarize( array $data, $version, $latest = '' ) {
		$items = self::affecting( $data, $version );

		// Records whose only fix is a version that doesn't exist for this product,
		// while the site already runs the newest published version, describe a
		// different edition (e.g. UpdraftPlus Premium 2.26.16.26 vs free 1.26.16).
		// They can't be acted on and the free edition is not affected: drop them.
		if ( '' !== (string) $latest && version_compare( (string) $version, (string) $latest, '>=' ) ) {
			$items = array_values(
				array_filter(
					$items,
					static function ( $i ) use ( $latest ) {
						return '' === $i['fixed_in'] || ! version_compare( $i['fixed_in'], (string) $latest, '>' );
					}
				)
			);
		}
		if ( ! $items ) {
			return null;
		}
		usort(
			$items,
			static function ( $a, $b ) {
				$d = self::SEVERITY_ORDER[ $b['severity'] ] - self::SEVERITY_ORDER[ $a['severity'] ];
				return 0 !== $d ? $d : strcmp( $a['title'], $b['title'] );
			}
		);
		$severity = $items[0]['severity'];
		$fixes    = array_values( array_filter( array_column( $items, 'fixed_in' ) ) );
		$unfixed  = in_array( true, array_column( $items, 'unfixed' ), true );
		$target   = self::recommendedVersion( (string) $version, $fixes, (string) $latest );

		// "<= X" records only tell us the fix is newer than X.
		$after = array_values( array_filter( array_column( $items, 'fixed_after' ) ) );
		$newer_than = '';
		if ( $after ) {
			usort( $after, 'version_compare' );
			$highest_after = (string) end( $after );
			if ( '' === $target || version_compare( $target, $highest_after, '<=' ) ) {
				if ( '' !== (string) $latest && version_compare( (string) $latest, $highest_after, '>' ) ) {
					$target = (string) $latest;
				} else {
					$target     = '';
					$newer_than = $highest_after;
				}
			}
		}

		return array(
			'count'    => count( $items ),
			'severity' => $severity,
			'fixed_in'   => $target,
			'newer_than' => $newer_than,
			'unfixed'    => $unfixed,
			'items'    => $items,
		);
	}

	/**
	 * The version to tell people to update to: the highest fix version, unless
	 * that version does not exist for this product. WPVulnerability sometimes
	 * records only the premium edition's fix (e.g. UpdraftPlus Premium 2.26.16.26
	 * while the free plugin was fixed in 1.26.16); in that case the latest version
	 * actually published is the right answer.
	 *
	 * @param string[] $fixes
	 * @param string   $latest Latest published version, if known (e.g. from wordpress.org).
	 */
	public static function recommendedVersion( $installed, array $fixes, $latest = '' ) {
		if ( ! $fixes ) {
			return '';
		}
		usort( $fixes, 'version_compare' );
		$highest = (string) end( $fixes );
		if ( '' !== (string) $latest && version_compare( $highest, $latest, '>' ) && version_compare( $latest, $installed, '>' ) ) {
			return (string) $latest;
		}
		return $highest;
	}

	/**
	 * Vulnerabilities that affect a specific installed version.
	 *
	 * @return array[] id, title, severity, rated, fixed_in, references
	 */
	public static function affecting( array $data, $version ) {
		$out = array();
		foreach ( isset( $data['vulnerability'] ) ? (array) $data['vulnerability'] : array() as $v ) {
			$op = isset( $v['operator'] ) ? (array) $v['operator'] : array();
			if ( ! self::versionMatches( $version, $op ) ) {
				continue;
			}
			$refs = array();
			foreach ( isset( $v['source'] ) ? (array) $v['source'] : array() as $s ) {
				if ( ! empty( $s['link'] ) ) {
					$refs[] = array(
						'id'          => isset( $s['id'] ) ? (string) $s['id'] : '',
						'name'        => isset( $s['name'] ) ? self::clean( $s['name'], true ) : '',
						'description' => isset( $s['description'] ) ? self::clean( $s['description'], false, true ) : '',
						'url'         => esc_url_raw( $s['link'] ),
					);
				}
			}
			$is_unfixed = ! empty( $op['unfixed'] );
			$max_op     = isset( $op['max_operator'] ) ? $op['max_operator'] : 'lt';
			// "< X": fixed in X. "<= X": fixed in some release after X (exact version not recorded).
			$fixed       = ( ! $is_unfixed && ! empty( $op['max_version'] ) && 'lt' === $max_op ) ? (string) $op['max_version'] : '';
			$fixed_after = ( ! $is_unfixed && ! empty( $op['max_version'] ) && 'le' === $max_op ) ? (string) $op['max_version'] : '';
			list( $severity, $rated ) = self::severity( $v );
			$out[] = array(
				'id'         => isset( $v['uuid'] ) ? (string) $v['uuid'] : md5( (string) wp_json_encode( $v ) ),
				'title'      => self::title( $v, $refs ),
				'severity'   => $severity,
				'rated'      => $rated,
				'fixed_in'    => $fixed,
				'fixed_after' => $fixed_after,
				'unfixed'     => $is_unfixed,
				'references'  => array_map(
					static function ( $r ) {
						unset( $r['description'] );
						return $r;
					},
					array_slice( $refs, 0, 5 )
				),
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

	/**
	 * Best human-readable title, in order of preference:
	 *   1. A source title of the form "Product <= 1.2 - Stored XSS" (text after the LAST " - ").
	 *   2. "…is vulnerable to <thing>" extracted from a description.
	 *   3. The start of a description.
	 *   4. A CVE id.
	 *   5. The database's own name (e.g. "Divi [Divi] < 4.27.7").
	 */
	public static function title( array $v, array $refs ) {
		foreach ( $refs as $r ) {
			$pos = strrpos( $r['name'], ' - ' );
			if ( false !== $pos ) {
				$t = trim( substr( $r['name'], $pos + 3 ) );
				if ( strlen( $t ) >= 8 && ! preg_match( '/^[\d.\s<>=-]+$/', $t ) ) {
					return self::truncate( $t );
				}
			}
		}
		$vulnerableTo = '/\bvulnerable to (?:an? )?([^\n]{6,140}?)(?: in (?:all )?versions?\b| via\b| due to\b| because\b|[.,;]|\n|$)/i';
		foreach ( array( 'name', 'description' ) as $field ) {
			foreach ( $refs as $r ) {
				if ( preg_match( $vulnerableTo, $r[ $field ], $m ) ) {
					return self::truncate( ucfirst( trim( $m[1] ) ) );
				}
			}
		}
		foreach ( $refs as $r ) {
			if ( '' !== $r['description'] ) {
				return self::truncate( strtok( $r['description'], "\n" ) );
			}
		}
		foreach ( $refs as $r ) {
			if ( 0 === strpos( $r['id'], 'CVE-' ) ) {
				return $r['id'];
			}
		}
		return isset( $v['name'] ) ? self::clean( $v['name'] ) : 'Known vulnerability';
	}

	/**
	 * @return array{0:string,1:bool} severity, and whether it came from a real rating.
	 */
	private static function severity( array $v ) {
		$impact = isset( $v['impact'] ) ? (array) $v['impact'] : array();
		if ( ! empty( $impact['ssvc']['kev'] ) ) {
			return array( 'critical', true ); // Listed in CISA's Known Exploited Vulnerabilities catalog.
		}
		if ( isset( $impact['cvss']['score'] ) && is_numeric( $impact['cvss']['score'] ) ) {
			$score = (float) $impact['cvss']['score'];
			if ( $score >= 9 ) {
				return array( 'critical', true );
			}
			if ( $score >= 7 ) {
				return array( 'high', true );
			}
			return array( $score >= 4 ? 'medium' : 'low', true );
		}
		return array( 'medium', false ); // Unrated: don't cry wolf.
	}

	/**
	 * Decode entities ("&#8211;", "&amp;"), strip tags and "[en]" language prefixes.
	 * Block-level tags become line breaks so "<p>A</p><p>B</p>" can't fuse into "AB";
	 * with $firstLine only the first non-empty line is kept (for titles).
	 */
	public static function clean( $text, $firstLine = false, $keepLines = false ) {
		$text = (string) preg_replace( '#<\s*(?:br\s*/?|/\s*(?:p|div|li|h[1-6]|tr|ul|ol|blockquote)\s*)>#i', "\n", (string) $text );
		$text = html_entity_decode( $text, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$text = wp_strip_all_tags( $text );
		$text = preg_replace( '/^\s*\[[a-z]{2}\]\s*/', '', $text );
		$lines = array_values( array_filter( array_map( 'trim', preg_split( '/\R/u', (string) $text ) ), 'strlen' ) );
		if ( ! $lines ) {
			return '';
		}
		if ( $firstLine ) {
			return trim( (string) preg_replace( '/\s+/u', ' ', $lines[0] ) );
		}
		if ( $keepLines ) {
			return implode( "\n", array_map( static function ( $l ) { return trim( (string) preg_replace( '/[^\S\n]+/u', ' ', $l ) ); }, $lines ) );
		}
		return trim( (string) preg_replace( '/\s+/u', ' ', implode( ' ', $lines ) ) );
	}

	private static function truncate( $text, $max = 110 ) {
		if ( function_exists( 'mb_strlen' ) ? mb_strlen( $text ) <= $max : strlen( $text ) <= $max ) {
			return $text;
		}
		$cut = function_exists( 'mb_substr' ) ? mb_substr( $text, 0, $max - 1 ) : substr( $text, 0, $max - 1 );
		return rtrim( $cut ) . '…';
	}
}


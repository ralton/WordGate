<?php
/**
 * Database content & option integrity audit helpers (pure logic, testable
 * without WordPress).
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class DatabaseAudit {

	const URLS_OPTION = 'wordgate_site_urls';

	/**
	 * Audit `siteurl` and `home` option values against:
	 *   1. Dangerous schemes / HTML injection (javascript:, <script, non-http(s))
	 *   2. WP_SITEURL / WP_HOME constants when defined
	 *   3. Unexpected host changes compared to the previous scan baseline
	 *
	 * @param array{siteurl:string,home:string}      $current
	 * @param array{siteurl:string,home:string}|null $previous  Null on first scan.
	 * @param array{siteurl?:string,home?:string}    $constants Optional WP_SITEURL/WP_HOME values.
	 * @return array[] Critical findings.
	 */
	public static function checkSiteUrls( array $current, $previous = null, array $constants = array() ) {
		$findings = array();
		foreach ( array( 'siteurl', 'home' ) as $opt ) {
			$val = isset( $current[ $opt ] ) ? trim( (string) $current[ $opt ] ) : '';
			if ( '' === $val ) {
				continue;
			}

			$parts  = parse_url( $val ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$scheme = is_array( $parts ) && isset( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : '';
			$host   = is_array( $parts ) && isset( $parts['host'] ) ? strtolower( $parts['host'] ) : '';

			if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || '' === $host || preg_match( '/[<>"\'`]/', $val ) ) {
				$findings[] = array(
					'type'        => 'option_url_tampered',
					'severity'    => 'critical',
					'title'       => sprintf( 'Critical option "%s" contains an invalid or injected URL', $opt ),
					'description' => sprintf( 'The "%s" option in wp_options is set to "%s", which is not a valid HTTP(S) URL. Attackers tamper with siteurl/home to hijack all visitors.', $opt, substr( $val, 0, 120 ) ),
					'subject'     => 'option_url_tampered:' . $opt,
					'data'        => array( 'option' => $opt, 'value' => $val ),
				);
				continue;
			}

			if ( ! empty( $constants[ $opt ] ) ) {
				$cParts = parse_url( trim( (string) $constants[ $opt ] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$cHost  = is_array( $cParts ) && isset( $cParts['host'] ) ? strtolower( $cParts['host'] ) : '';
				if ( '' !== $cHost && $cHost !== $host ) {
					$findings[] = array(
						'type'        => 'option_url_tampered',
						'severity'    => 'critical',
						'title'       => sprintf( 'Option "%s" (%s) disagrees with wp-config.php constant (%s)', $opt, $host, $cHost ),
						'description' => sprintf( 'The database value for "%s" points to a different host than the constant defined in wp-config.php. Check wp_options for tampering.', $opt ),
						'subject'     => 'option_url_const:' . $opt,
						'data'        => array( 'option' => $opt, 'value' => $val, 'expected' => $constants[ $opt ] ),
					);
					continue;
				}
			}

			if ( is_array( $previous ) && ! empty( $previous[ $opt ] ) ) {
				$pParts = parse_url( trim( (string) $previous[ $opt ] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$pHost  = is_array( $pParts ) && isset( $pParts['host'] ) ? strtolower( $pParts['host'] ) : '';
				if ( '' !== $pHost && $pHost !== $host ) {
					$findings[] = array(
						'type'        => 'option_url_changed',
						'severity'    => 'critical',
						'title'       => sprintf( 'Option "%s" host changed from %s to %s', $opt, $pHost, $host ),
						'description' => sprintf( 'The "%s" option changed domain since the previous scan. Unless you intentionally migrated domains, this is a strong sign of siteurl hijacking.', $opt ),
						'subject'     => 'option_url_changed:' . $opt . ':' . $host,
						'data'        => array( 'option' => $opt, 'previous' => $previous[ $opt ], 'value' => $val ),
					);
				}
			}
		}
		return $findings;
	}
}

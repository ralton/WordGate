<?php
/**
 * IP address helpers (IPv4 + IPv6, CIDR matching).
 *
 * This file is loaded by the WAF before WordPress, so it must not depend on
 * any WordPress function.
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class IpUtil {

	/**
	 * Is the value a syntactically valid IPv4 or IPv6 address?
	 */
	public static function isValid( $ip ) {
		return is_string( $ip ) && false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Is the value a valid IP or CIDR range (e.g. 10.0.0.0/8, 2001:db8::/32)?
	 */
	public static function isValidRange( $range ) {
		if ( ! is_string( $range ) || '' === $range ) {
			return false;
		}
		if ( false === strpos( $range, '/' ) ) {
			return self::isValid( $range );
		}
		list( $subnet, $bits ) = explode( '/', $range, 2 );
		if ( ! self::isValid( $subnet ) || ! ctype_digit( $bits ) ) {
			return false;
		}
		$max = false !== strpos( $subnet, ':' ) ? 128 : 32;
		return (int) $bits <= $max;
	}

	/**
	 * Does $ip fall inside $range (single IP or CIDR)?
	 */
	public static function inRange( $ip, $range ) {
		$ipBin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $ipBin ) {
			return false;
		}

		if ( false === strpos( $range, '/' ) ) {
			$rangeBin = @inet_pton( $range ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false !== $rangeBin && $rangeBin === $ipBin;
		}

		list( $subnet, $bits ) = explode( '/', $range, 2 );
		$subnetBin             = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $subnetBin || strlen( $subnetBin ) !== strlen( $ipBin ) ) {
			// Allow IPv4 to match an IPv4-mapped IPv6 range and vice versa.
			$ipBin     = self::normalizeMapped( $ipBin );
			$subnetBin = false === $subnetBin ? false : self::normalizeMapped( $subnetBin );
			if ( false === $subnetBin || strlen( $subnetBin ) !== strlen( $ipBin ) ) {
				return false;
			}
		}

		$bits      = (int) $bits;
		$fullBytes = intdiv( $bits, 8 );
		$remainder = $bits % 8;

		if ( $fullBytes > 0 && substr( $ipBin, 0, $fullBytes ) !== substr( $subnetBin, 0, $fullBytes ) ) {
			return false;
		}
		if ( 0 === $remainder ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $remainder ) ) & 0xFF;
		return ( ord( $ipBin[ $fullBytes ] ) & $mask ) === ( ord( $subnetBin[ $fullBytes ] ) & $mask );
	}

	/**
	 * Does $ip match any entry of $ranges?
	 *
	 * @param string   $ip     Address to test.
	 * @param string[] $ranges List of IPs / CIDRs.
	 */
	public static function matchesAny( $ip, array $ranges ) {
		foreach ( $ranges as $range ) {
			if ( is_string( $range ) && '' !== $range && self::inRange( $ip, trim( $range ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Canonical text form, so that "::ffff:1.2.3.4" and "1.2.3.4" compare equal.
	 */
	public static function normalize( $ip ) {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $bin ) {
			return '';
		}
		return (string) inet_ntop( self::normalizeMapped( $bin ) );
	}

	/**
	 * Convert IPv4-mapped IPv6 (::ffff:a.b.c.d) to 4-byte IPv4.
	 */
	private static function normalizeMapped( $bin ) {
		if ( 16 === strlen( $bin ) && 0 === strncmp( $bin, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
			return substr( $bin, 12 );
		}
		return $bin;
	}

	/**
	 * Resolve the client IP.
	 *
	 * By default only REMOTE_ADDR is trusted. A forwarding header is only honoured
	 * when the immediate peer (REMOTE_ADDR) is a configured trusted proxy;
	 * otherwise any client could spoof its address.
	 *
	 * @param array    $server         Typically $_SERVER.
	 * @param string   $source         'REMOTE_ADDR' or a header such as 'HTTP_X_FORWARDED_FOR'.
	 * @param string[] $trustedProxies IPs / CIDRs allowed to set $source.
	 */
	public static function clientIp( array $server, $source = 'REMOTE_ADDR', array $trustedProxies = array() ) {
		$remote = isset( $server['REMOTE_ADDR'] ) ? trim( (string) $server['REMOTE_ADDR'] ) : '';
		$remote = self::isValid( $remote ) ? self::normalize( $remote ) : '127.0.0.1';

		if ( 'REMOTE_ADDR' === $source || empty( $server[ $source ] ) ) {
			return $remote;
		}

		// Cloud proxies such as Cloudflare: if no proxy list is configured we
		// refuse to trust the header, because that would allow trivial spoofing.
		if ( empty( $trustedProxies ) || ! self::matchesAny( $remote, $trustedProxies ) ) {
			return $remote;
		}

		// X-Forwarded-For: client, proxy1, proxy2. Walk right-to-left and return
		// the first hop that is not itself a trusted proxy.
		$hops = array_reverse( array_map( 'trim', explode( ',', (string) $server[ $source ] ) ) );
		foreach ( $hops as $hop ) {
			// Strip an optional port ("1.2.3.4:5678" or "[2001:db8::1]:443").
			if ( preg_match( '/^\[([^\]]+)\](?::\d+)?$/', $hop, $m ) ) {
				$hop = $m[1];
			} elseif ( substr_count( $hop, ':' ) === 1 ) {
				$hop = explode( ':', $hop )[0];
			}
			if ( ! self::isValid( $hop ) ) {
				continue;
			}
			$hop = self::normalize( $hop );
			if ( ! self::matchesAny( $hop, $trustedProxies ) ) {
				return $hop;
			}
		}
		return $remote;
	}
}

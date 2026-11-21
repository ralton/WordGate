<?php
/**
 * RFC 6238 time-based one-time passwords (Google Authenticator, 1Password,
 * Authy, Bitwarden, etc.). No WordPress dependency.
 *
 * @package WordGate
 */

namespace WordGate\Login;

final class Totp {

	const PERIOD = 30;
	const DIGITS = 6;
	const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a random base32 secret (160 bits, as recommended by RFC 4226).
	 */
	public static function generateSecret( $bytes = 20 ) {
		return self::base32Encode( random_bytes( $bytes ) );
	}

	/**
	 * Compute the code for a given time step.
	 *
	 * @param string $secretBase32 Shared secret.
	 * @param int    $counter      Time step (floor(unix / period)).
	 * @param int    $digits       Code length.
	 * @param string $algo         sha1 | sha256 | sha512.
	 */
	public static function code( $secretBase32, $counter, $digits = self::DIGITS, $algo = 'sha1' ) {
		$key  = self::base32Decode( $secretBase32 );
		$bin  = pack( 'J', $counter ); // 64-bit big-endian.
		$hash = hash_hmac( $algo, $bin, $key, true );
		$off  = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$val  = ( ( ord( $hash[ $off ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $off + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $off + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $off + 3 ] ) & 0xFF );
		return str_pad( (string) ( $val % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a user-supplied code, allowing ±$window steps of clock drift.
	 *
	 * Returns the matched time step (so callers can reject replays of a code
	 * that was already used) or false.
	 *
	 * @param int|null $lastUsedStep Reject codes at or before this step (replay protection).
	 * @return int|false
	 */
	public static function verify( $secretBase32, $code, $window = 1, $now = null, $lastUsedStep = null ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{6}$/', $code ) || '' === (string) $secretBase32 ) {
			return false;
		}
		$step = intdiv( null === $now ? time() : (int) $now, self::PERIOD );
		for ( $i = -$window; $i <= $window; $i++ ) {
			$candidate = $step + $i;
			if ( null !== $lastUsedStep && $candidate <= (int) $lastUsedStep ) {
				continue;
			}
			if ( hash_equals( self::code( $secretBase32, $candidate ), $code ) ) {
				return $candidate;
			}
		}
		return false;
	}

	/**
	 * otpauth:// URI for QR codes.
	 */
	public static function provisioningUri( $secret, $account, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );
		return 'otpauth://totp/' . $label . '?' . http_build_query(
			array(
				'secret'    => $secret,
				'issuer'    => $issuer,
				'algorithm' => 'SHA1',
				'digits'    => self::DIGITS,
				'period'    => self::PERIOD,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}

	public static function base32Encode( $data ) {
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$len    = strlen( $data );
		for ( $i = 0; $i < $len; $i++ ) {
			$buffer = ( $buffer << 8 ) | ord( $data[ $i ] );
			$bits  += 8;
			while ( $bits >= 5 ) {
				$bits -= 5;
				$out  .= self::BASE32[ ( $buffer >> $bits ) & 31 ];
			}
		}
		if ( $bits > 0 ) {
			$out .= self::BASE32[ ( $buffer << ( 5 - $bits ) ) & 31 ];
		}
		return $out;
	}

	public static function base32Decode( $b32 ) {
		$b32    = strtoupper( preg_replace( '/[\s=-]+/', '', (string) $b32 ) );
		$out    = '';
		$buffer = 0;
		$bits   = 0;
		$len    = strlen( $b32 );
		for ( $i = 0; $i < $len; $i++ ) {
			$v = strpos( self::BASE32, $b32[ $i ] );
			if ( false === $v ) {
				continue;
			}
			$buffer = ( ( $buffer << 5 ) | $v ) & 0xFFFFFF;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits -= 8;
				$out  .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $out;
	}
}

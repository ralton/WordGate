<?php
/**
 * Normalisation transforms applied to a value before pattern matching, so
 * that trivial encodings (double URL-encoding, entities, comments, case)
 * cannot be used to slip past rules.
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Transforms {

	/** @var array<string,string> Per-request memoisation keyed by chain + value hash. */
	private static $cache = array();

	public static function apply( $value, array $chain ) {
		if ( empty( $chain ) ) {
			return $value;
		}
		$key = implode( ',', $chain ) . ':' . md5( $value );
		if ( isset( self::$cache[ $key ] ) ) {
			return self::$cache[ $key ];
		}
		foreach ( $chain as $t ) {
			$value = self::one( $t, $value );
		}
		if ( count( self::$cache ) > 2048 ) {
			self::$cache = array();
		}
		self::$cache[ $key ] = $value;
		return $value;
	}

	private static function one( $name, $v ) {
		switch ( $name ) {
			case 'urldecode':
				// PHP has already decoded once; decode up to twice more to defeat double-encoding.
				for ( $i = 0; $i < 2; $i++ ) {
					$d = rawurldecode( str_replace( '+', ' ', $v ) );
					if ( $d === $v ) {
						break;
					}
					$v = $d;
				}
				return $v;
			case 'html_entity_decode':
				return html_entity_decode( $v, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			case 'lowercase':
				return strtolower( $v );
			case 'remove_nulls':
				return str_replace( "\0", '', $v );
			case 'compress_whitespace':
				return (string) preg_replace( '/[\s\x0b]+/', ' ', $v );
			case 'remove_sql_comments':
				// Unwrap MySQL conditional comments (/*!50000...*/), then strip standard /* ... */ comments.
				$v = (string) preg_replace( '#/\*!\d*(.*?)\*/#s', ' $1 ', $v );
				$v = (string) preg_replace( '#/\*.*?\*/#s', ' ', $v );
				return $v;
			case 'normalize_path':
				$v = str_replace( '\\', '/', $v );
				$v = (string) preg_replace( '#(?<!:)/{2,}#', '/', $v ); // Keep scheme://.
				return (string) preg_replace( '#/\./#', '/', $v );
			case 'base64_decode':
				$d = base64_decode( $v, true );
				return false === $d ? $v : $d;
		}
		return $v;
	}
}

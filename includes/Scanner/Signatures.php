<?php
/**
 * Malware signature matcher. No WordPress dependency.
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class Signatures {

	/** @var array[] */
	private $sigs = array();

	public function __construct( array $signatures ) {
		foreach ( $signatures as $s ) {
			if ( empty( $s['id'] ) || empty( $s['pattern'] ) ) {
				continue;
			}
			$s['regex']  = '#' . str_replace( '#', '\\#', $s['pattern'] ) . '#iS';
			$s['types']  = isset( $s['types'] ) ? array_map( 'strtolower', (array) $s['types'] ) : array();
			$this->sigs[] = $s;
		}
	}

	public static function fromFile( $file, $key = 'signatures' ) {
		$data = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return new self( is_array( $data ) && isset( $data[ $key ] ) ? $data[ $key ] : array() );
	}

	public function count() {
		return count( $this->sigs );
	}

	/**
	 * File extensions that are worth reading at all.
	 *
	 * @return string[]
	 */
	public function extensions() {
		$ext = array();
		foreach ( $this->sigs as $s ) {
			$ext = array_merge( $ext, $s['types'] );
		}
		return array_values( array_unique( $ext ) );
	}

	/**
	 * Scan content and return all matching signatures.
	 *
	 * @param string $content   File contents.
	 * @param string $extension Lower-case file extension, or '' to apply all signatures.
	 * @return array[] Each: id, name, severity, matched (snippet), offset.
	 */
	public function scan( $content, $extension = '' ) {
		$hits = array();
		foreach ( $this->sigs as $s ) {
			if ( '' !== $extension && $s['types'] && ! in_array( $extension, $s['types'], true ) ) {
				continue;
			}
			if ( preg_match( $s['regex'], $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = array(
					'id'       => $s['id'],
					'name'     => $s['name'],
					'severity' => $s['severity'],
					'matched'  => substr( $m[0][0], 0, 160 ),
					'offset'   => $m[0][1],
				);
			}
		}
		return $hits;
	}

	/**
	 * Validate every pattern compiles. Returns ids of broken signatures.
	 *
	 * @return string[]
	 */
	public function invalid() {
		$bad = array();
		foreach ( $this->sigs as $s ) {
			if ( false === @preg_match( $s['regex'], '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$bad[] = $s['id'];
			}
		}
		return $bad;
	}
}

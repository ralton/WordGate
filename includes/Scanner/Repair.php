<?php
/**
 * One-click fixes for scan issues: restore an original core/plugin file
 * (verified against the official checksum before writing) or delete a file.
 *
 * @package WordGate
 */

namespace WordGate\Scanner;

final class Repair {

	/**
	 * @return true|\WP_Error
	 */
	public static function apply( array $issue, $action ) {
		$file = (string) $issue['file'];
		$data = (array) $issue['data'];
		if ( '' === $file || ! self::isSafePath( $file ) ) {
			return new \WP_Error( 'wordgate_path', __( 'Refusing to modify a file outside the WordPress installation.', 'wordgate' ) );
		}

		if ( 'restore' === $action && isset( $data['repair'] ) && in_array( $data['repair'], array( 'core', 'plugin' ), true ) ) {
			if ( 'core' === $data['repair'] ) {
				$url      = sprintf( 'https://core.svn.wordpress.org/tags/%s/%s', rawurlencode( $data['version'] ), self::encodePath( $data['rel'] ) );
				$expected = array( $data['md5'] );
			} else {
				$url      = sprintf( 'https://plugins.svn.wordpress.org/%s/tags/%s/%s', rawurlencode( $data['slug'] ), rawurlencode( $data['version'] ), self::encodePath( $data['rel'] ) );
				$expected = (array) $data['md5'];
			}
			$res = wp_remote_get( $url, array( 'timeout' => 20 ) );
			if ( 200 !== wp_remote_retrieve_response_code( $res ) && 'plugin' === $data['repair'] ) {
				// Some plugins ship from trunk without tagging releases.
				$res = wp_remote_get( sprintf( 'https://plugins.svn.wordpress.org/%s/trunk/%s', rawurlencode( $data['slug'] ), self::encodePath( $data['rel'] ) ), array( 'timeout' => 20 ) );
			}
			$body = wp_remote_retrieve_body( $res );
			if ( 200 !== wp_remote_retrieve_response_code( $res ) || ! in_array( md5( $body ), $expected, true ) ) {
				return new \WP_Error( 'wordgate_download', __( 'Could not download a verified original copy of this file. Reinstall the plugin or WordPress instead.', 'wordgate' ) );
			}
			if ( false === file_put_contents( $file, $body ) ) { // phpcs:ignore
				return new \WP_Error( 'wordgate_write', __( 'The file could not be written. Check file permissions.', 'wordgate' ) );
			}
			Issues::setStatus( $issue['id'], 'resolved' );
			return true;
		}

		if ( 'delete' === $action && isset( $data['repair'] ) && 'delete' === $data['repair'] ) {
			if ( ! file_exists( $file ) ) {
				Issues::setStatus( $issue['id'], 'resolved' );
				return true;
			}
			if ( ! @unlink( $file ) ) { // phpcs:ignore
				return new \WP_Error( 'wordgate_delete', __( 'The file could not be deleted. Check file permissions.', 'wordgate' ) );
			}
			Issues::setStatus( $issue['id'], 'resolved' );
			return true;
		}

		return new \WP_Error( 'wordgate_action', __( 'This action is not available for this issue.', 'wordgate' ) );
	}

	private static function encodePath( $rel ) {
		return implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) );
	}

	/**
	 * Only files inside ABSPATH or WP_CONTENT_DIR, never wp-config.php.
	 */
	public static function isSafePath( $file ) {
		$real = realpath( $file );
		if ( false === $real ) {
			$real = realpath( dirname( $file ) );
			if ( false === $real ) {
				return false;
			}
			$real .= '/' . basename( $file );
		}
		if ( 'wp-config.php' === basename( $real ) ) {
			return false;
		}
		foreach ( array( ABSPATH, WP_CONTENT_DIR ) as $root ) {
			$root = realpath( $root );
			if ( $root && 0 === strpos( $real, rtrim( $root, '/' ) . '/' ) ) {
				return true;
			}
		}
		return false;
	}
}

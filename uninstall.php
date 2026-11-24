<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 *
 * @package WordGate
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

$wordgate_settings = get_option( 'wordgate_settings', array() );
if ( empty( $wordgate_settings['delete_data_on_uninstall'] ) ) {
	return;
}

global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wordgate_events" ); // phpcs:ignore
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wordgate_issues" ); // phpcs:ignore

foreach ( array( 'wordgate_settings', 'wordgate_db_version', 'wordgate_auth_secret', 'wordgate_scan_state', 'wordgate_last_scan' ) as $wordgate_opt ) {
	delete_option( $wordgate_opt );
}
foreach ( array( 'wordgate_2fa', 'wordgate_2fa_pending', 'wordgate_2fa_grace_start' ) as $wordgate_meta ) {
	delete_metadata( 'user', 0, $wordgate_meta, '', true );
}
remove_role( 'wordgate_auditor' );

$wordgate_stub    = ABSPATH . 'wordgate-waf.php';
$wordgate_prepend = (string) ini_get( 'auto_prepend_file' );
if ( file_exists( $wordgate_stub ) && ( '' === $wordgate_prepend || realpath( $wordgate_prepend ) !== realpath( $wordgate_stub ) ) ) {
	@unlink( $wordgate_stub ); // phpcs:ignore
}
wp_clear_scheduled_hook( 'wordgate_delete_waf_stub' );

$wordgate_uploads = wp_get_upload_dir();
if ( ! empty( $wordgate_uploads['basedir'] ) ) {
	$wordgate_uht = rtrim( (string) $wordgate_uploads['basedir'], '/\\' ) . '/.htaccess';
	if ( file_exists( $wordgate_uht ) ) {
		$wordgate_c = (string) file_get_contents( $wordgate_uht ); // phpcs:ignore
		$wordgate_n = (string) preg_replace( "/# BEGIN WordGate Uploads Protection\n.*?# END WordGate Uploads Protection\n?/s", '', $wordgate_c );
		if ( $wordgate_n !== $wordgate_c ) {
			@file_put_contents( $wordgate_uht, $wordgate_n ); // phpcs:ignore
		}
	}
}

$wordgate_dir = defined( 'WORDGATE_DATA_DIR' ) ? WORDGATE_DATA_DIR : WP_CONTENT_DIR . '/wordgate';
if ( is_dir( $wordgate_dir ) ) {
	$wordgate_it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $wordgate_dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $wordgate_it as $wordgate_file ) {
		$wordgate_file->isDir() ? rmdir( $wordgate_file->getPathname() ) : unlink( $wordgate_file->getPathname() ); // phpcs:ignore
	}
	rmdir( $wordgate_dir ); // phpcs:ignore
}

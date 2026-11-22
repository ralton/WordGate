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

$wordgate_dir = defined( 'WORDGATE_DATA_DIR' ) ? WORDGATE_DATA_DIR : WP_CONTENT_DIR . '/wordgate';
if ( is_dir( $wordgate_dir ) ) {
	$wordgate_it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $wordgate_dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
	foreach ( $wordgate_it as $wordgate_file ) {
		$wordgate_file->isDir() ? rmdir( $wordgate_file->getPathname() ) : unlink( $wordgate_file->getPathname() ); // phpcs:ignore
	}
	rmdir( $wordgate_dir ); // phpcs:ignore
}

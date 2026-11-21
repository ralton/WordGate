<?php
/**
 * Activation, deactivation and schema upgrades.
 *
 * @package WordGate
 */

namespace WordGate;

use WordGate\Firewall\WafConfig;
use WordGate\Firewall\WafInstaller;

final class Installer {

	const DB_VERSION = '1';

	public static function activate() {
		self::upgrade();
		Plugin::storage()->ensureDir();
		WafConfig::sync();
		WafInstaller::installBasic();
		self::scheduleCron();
	}

	public static function deactivate() {
		// The WAF must not keep running once the plugin is off.
		WafInstaller::uninstallBasic();
		WafInstaller::uninstallExtended();
		wp_clear_scheduled_hook( 'wordgate_hourly' );
		wp_clear_scheduled_hook( 'wordgate_daily' );
		wp_clear_scheduled_hook( 'wordgate_scheduled_scan' );
		wp_clear_scheduled_hook( 'wordgate_scan_continue' );
	}

	public static function scheduleCron() {
		if ( ! wp_next_scheduled( 'wordgate_hourly' ) ) {
			wp_schedule_event( time() + 300, 'hourly', 'wordgate_hourly' );
		}
		if ( ! wp_next_scheduled( 'wordgate_daily' ) ) {
			wp_schedule_event( time() + 600, 'daily', 'wordgate_daily' );
		}
	}

	public static function upgrade() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();

		dbDelta(
			"CREATE TABLE {$wpdb->prefix}wordgate_events (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created int(10) unsigned NOT NULL,
				type varchar(32) NOT NULL,
				severity varchar(16) NOT NULL DEFAULT 'info',
				ip varchar(45) NOT NULL DEFAULT '',
				user_login varchar(60) NOT NULL DEFAULT '',
				method varchar(10) NOT NULL DEFAULT '',
				uri text NOT NULL,
				rule_id int(10) unsigned NOT NULL DEFAULT 0,
				reason varchar(255) NOT NULL DEFAULT '',
				details longtext NOT NULL,
				PRIMARY KEY  (id),
				KEY created (created),
				KEY type_created (type,created),
				KEY ip (ip)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$wpdb->prefix}wordgate_issues (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				hash char(40) NOT NULL,
				type varchar(40) NOT NULL,
				severity varchar(16) NOT NULL,
				status varchar(16) NOT NULL DEFAULT 'open',
				title varchar(255) NOT NULL,
				description text NOT NULL,
				file varchar(1024) NOT NULL DEFAULT '',
				data longtext NOT NULL,
				first_seen int(10) unsigned NOT NULL,
				last_seen int(10) unsigned NOT NULL,
				scan_id int(10) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				UNIQUE KEY hash (hash),
				KEY status (status)
			) {$charset};"
		);

		update_option( 'wordgate_db_version', self::DB_VERSION, true );
		self::scheduleCron();
	}
}

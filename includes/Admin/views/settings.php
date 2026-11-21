<?php
/**
 * General settings view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;

defined( 'ABSPATH' ) || exit;

Admin::formStart( 'settings' );
?>
<div class="wg-panel">
	<h2><?php esc_html_e( 'Hardening', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::select(
			'xmlrpc',
			__( 'XML-RPC', 'wordgate' ),
			array(
				'on'      => __( 'Enabled (WordPress default)', 'wordgate' ),
				'no_auth' => __( 'Disable logins via XML-RPC (pingbacks still work)', 'wordgate' ),
				'off'     => __( 'Disable completely', 'wordgate' ),
			),
			__( 'XML-RPC is a common brute-force target. Jetpack and some apps need it.', 'wordgate' )
		);
		Admin::checkbox( 'block_author_enum', __( 'Block username discovery', 'wordgate' ), __( 'Stops ?author=N scans, removes authors from oEmbed data and the user sitemap.', 'wordgate' ) );
		Admin::checkbox( 'restrict_rest_users', __( 'Hide REST API user list', 'wordgate' ), __( 'Logged-out visitors can no longer list users at /wp-json/wp/v2/users.', 'wordgate' ) );
		Admin::checkbox( 'hide_wp_version', __( 'Hide WordPress version', 'wordgate' ) );
		Admin::checkbox( 'disable_file_editor', __( 'Disable theme & plugin file editor', 'wordgate' ), __( 'Prevents a stolen admin session from being turned into code execution through Appearance → Theme File Editor.', 'wordgate' ) );
		Admin::checkbox( 'security_headers', __( 'Security headers', 'wordgate' ), __( 'Sends X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy and (on HTTPS) HSTS.', 'wordgate' ) );
		?>
	</table>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Scanner', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::select(
			'scan_schedule',
			__( 'Automatic scans', 'wordgate' ),
			array(
				'daily'  => __( 'Daily', 'wordgate' ),
				'weekly' => __( 'Weekly', 'wordgate' ),
				'off'    => __( 'Off', 'wordgate' ),
			)
		);
		Admin::checkbox( 'vuln_check', __( 'Check for known vulnerabilities', 'wordgate' ), __( 'Looks up installed plugin and theme slugs in the open <a href="https://www.wpvulnerability.net/" target="_blank" rel="noopener">WPVulnerability</a> database. Your site URL is never sent.', 'wordgate' ) );
		Admin::checkbox( 'scan_uploads', __( 'Scan media uploads', 'wordgate' ), __( 'Scan HTML/JS/SVG files in uploads for malware. PHP files in uploads are always flagged.', 'wordgate' ) );
		Admin::number( 'scan_max_file_kb', __( 'Skip files larger than', 'wordgate' ), '', 'KB' );
		?>
	</table>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Email alerts', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::text( 'notify_email', __( 'Send alerts to', 'wordgate' ), __( 'Leave empty to use the site admin email.', 'wordgate' ), get_option( 'admin_email' ) );
		Admin::checkbox( 'notify_scan', __( 'New scan issues', 'wordgate' ) );
		Admin::checkbox( 'notify_admin_lockout', __( 'Administrator account locked out', 'wordgate' ) );
		Admin::checkbox( 'notify_admin_login', __( 'Every administrator login', 'wordgate' ) );
		?>
	</table>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Data', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::number( 'log_retention_days', __( 'Keep activity log for', 'wordgate' ), '', __( 'days', 'wordgate' ) );
		Admin::checkbox( 'delete_data_on_uninstall', __( 'Delete all data on uninstall', 'wordgate' ), __( 'Removes settings, logs, blocks and users\' 2FA configuration when the plugin is deleted.', 'wordgate' ) );
		?>
	</table>
</div>
<?php
Admin::formEnd();

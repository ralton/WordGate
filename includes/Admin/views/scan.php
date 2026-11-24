<?php
/**
 * Scanner view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Scanner\Issues;
use WordGate\Scanner\ScanRunner;

defined( 'ABSPATH' ) || exit;

$wg_tab     = isset( $_GET['status'] ) && in_array( $_GET['status'], array( 'open', 'ignored', 'resolved' ), true ) ? sanitize_key( $_GET['status'] ) : 'open'; // phpcs:ignore WordPress.Security.NonceVerification
$wg_issues  = Issues::all( $wg_tab );
$wg_counts  = Issues::counts();
$wg_last    = get_option( ScanRunner::LAST );
$wg_running = ScanRunner::isRunning();
?>
<div class="wg-panel wg-scan-head">
	<div>
		<h2><?php esc_html_e( 'Security scan', 'wordgate' ); ?></h2>
		<p>
			<?php
			if ( $wg_last ) {
				echo esc_html(
					sprintf(
						/* translators: 1: time ago, 2: files, 3: seconds */
						__( 'Last scan %1$s: %2$s files checked in %3$s seconds.', 'wordgate' ),
						Admin::timeAgo( $wg_last['finished'] ),
						number_format_i18n( $wg_last['files_scanned'] ),
						number_format_i18n( $wg_last['finished'] - $wg_last['started'] )
					)
				);
				foreach ( (array) $wg_last['notes'] as $wg_note ) {
					echo '<br><em>' . esc_html( $wg_note ) . '</em>';
				}
			} else {
				esc_html_e( 'Checks core and plugin files against official checksums, looks up known vulnerabilities, scans for malware signatures and reviews your configuration.', 'wordgate' );
			}
			?>
		</p>
	</div>
	<div class="wg-scan-actions">
		<button type="button" class="button button-primary button-hero" id="wg-scan-start" <?php disabled( $wg_running ); ?> data-running="<?php echo $wg_running ? '1' : '0'; ?>"><?php $wg_running ? esc_html_e( 'Scan running…', 'wordgate' ) : esc_html_e( 'Start scan', 'wordgate' ); ?></button>
	</div>
	<div id="wg-scan-progress" hidden>
		<div class="wg-progress"><span style="width:0%"></span></div>
		<p id="wg-scan-phase" aria-live="polite"></p>
	</div>
</div>

<ul class="subsubsub">
	<?php foreach ( array( 'open' => __( 'Open', 'wordgate' ), 'ignored' => __( 'Ignored', 'wordgate' ), 'resolved' => __( 'Resolved', 'wordgate' ) ) as $wg_k => $wg_label ) : ?>
		<li><a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-scan&status=' . $wg_k ) ); ?>" class="<?php echo $wg_tab === $wg_k ? 'current' : ''; ?>"><?php echo esc_html( $wg_label ); ?> <span class="count">(<?php echo (int) $wg_counts[ $wg_k ]; ?>)</span></a><?php echo 'resolved' !== $wg_k ? ' |' : ''; ?></li>
	<?php endforeach; ?>
</ul>
<br class="clear" />

<?php if ( ! $wg_issues ) : ?>
	<div class="wg-panel wg-empty-state">
		<span class="dashicons dashicons-yes-alt"></span>
		<p><?php echo 'open' === $wg_tab ? esc_html__( 'No open issues.', 'wordgate' ) : esc_html__( 'Nothing here.', 'wordgate' ); ?></p>
	</div>
<?php else : ?>
	<div class="wg-issues">
	<?php foreach ( $wg_issues as $wg_issue ) : $wg_data = (array) $wg_issue['data']; ?>
		<details class="wg-issue wg-issue-<?php echo esc_attr( $wg_issue['severity'] ); ?>">
			<summary>
				<?php echo Admin::severityBadge( $wg_issue['severity'] ); // phpcs:ignore ?>
				<span class="wg-issue-title"><?php echo esc_html( $wg_issue['title'] ); ?></span>
				<span class="wg-issue-when"><?php echo esc_html( Admin::timeAgo( $wg_issue['first_seen'] ) ); ?></span>
			</summary>
			<div class="wg-issue-body">
				<p><?php echo esc_html( $wg_issue['description'] ); ?></p>
				<?php if ( $wg_issue['file'] ) : ?>
					<p><strong><?php esc_html_e( 'File:', 'wordgate' ); ?></strong> <code><?php echo esc_html( ScanRunner::rel( $wg_issue['file'] ) ); ?></code>
					<?php if ( file_exists( $wg_issue['file'] ) ) : ?>
						— <?php echo esc_html( size_format( filesize( $wg_issue['file'] ) ) ); ?>, <?php echo esc_html( sprintf( __( 'modified %s', 'wordgate' ), Admin::timeAgo( filemtime( $wg_issue['file'] ) ) ) ); ?>
					<?php endif; ?></p>
				<?php endif; ?>
				<?php if ( ! empty( $wg_data['sha256'] ) ) : ?>
					<p><strong><?php esc_html_e( 'SHA-256:', 'wordgate' ); ?></strong> <code><?php echo esc_html( $wg_data['sha256'] ); ?></code></p>
				<?php endif; ?>
				<?php if ( ! empty( $wg_data['matched'] ) ) : ?>
					<p><strong><?php esc_html_e( 'Matched code:', 'wordgate' ); ?></strong></p><pre class="wg-code"><?php echo esc_html( $wg_data['matched'] ); ?></pre>
				<?php endif; ?>
				<?php if ( ! empty( $wg_data['references'] ) ) : ?>
					<p><strong><?php esc_html_e( 'References:', 'wordgate' ); ?></strong>
					<?php foreach ( $wg_data['references'] as $wg_ref ) : ?>
						<a href="<?php echo esc_url( $wg_ref['url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $wg_ref['id'] && strlen( $wg_ref['id'] ) < 24 ? $wg_ref['id'] : wp_parse_url( $wg_ref['url'], PHP_URL_HOST ) ); ?></a>
					<?php endforeach; ?></p>
				<?php endif; ?>
				<?php if ( ! empty( $wg_data['vulnerabilities'] ) ) : ?>
					<table class="widefat striped wg-vulns">
						<thead><tr><th><?php esc_html_e( 'Severity', 'wordgate' ); ?></th><th><?php esc_html_e( 'Vulnerability', 'wordgate' ); ?></th><th><?php esc_html_e( 'Fixed in', 'wordgate' ); ?></th><th><?php esc_html_e( 'References', 'wordgate' ); ?></th></tr></thead>
						<tbody>
						<?php foreach ( $wg_data['vulnerabilities'] as $wg_v ) : ?>
							<tr>
								<td><?php echo Admin::severityBadge( $wg_v['severity'] ); // phpcs:ignore ?><?php echo empty( $wg_v['rated'] ) ? ' <small title="' . esc_attr__( 'No CVSS score published', 'wordgate' ) . '">' . esc_html__( 'unrated', 'wordgate' ) . '</small>' : ''; ?></td>
								<td><?php echo esc_html( $wg_v['title'] ); ?></td>
								<td>
									<?php
									if ( $wg_v['fixed_in'] ) {
										echo esc_html( $wg_v['fixed_in'] );
									} elseif ( ! empty( $wg_v['fixed_after'] ) ) {
										/* translators: %s: version */
										echo esc_html( sprintf( __( 'after %s', 'wordgate' ), $wg_v['fixed_after'] ) );
									} else {
										esc_html_e( 'No fix', 'wordgate' );
									}
									?>
								</td>
								<td>
									<?php foreach ( (array) $wg_v['references'] as $wg_ref ) : ?>
										<a href="<?php echo esc_url( $wg_ref['url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $wg_ref['id'] && strlen( $wg_ref['id'] ) < 24 ? $wg_ref['id'] : wp_parse_url( $wg_ref['url'], PHP_URL_HOST ) ); ?></a>
									<?php endforeach; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
				<p class="wg-issue-actions">
					<?php if ( 'open' === $wg_issue['status'] ) : ?>
						<?php if ( isset( $wg_data['repair'] ) && in_array( $wg_data['repair'], array( 'core', 'plugin' ), true ) ) : ?>
							<a class="button button-primary" href="<?php echo esc_url( Admin::actionUrl( 'issue', array( 'id' => $wg_issue['id'], 'op' => 'restore' ) ) ); ?>"><?php esc_html_e( 'Restore original file', 'wordgate' ); ?></a>
						<?php endif; ?>
						<?php if ( isset( $wg_data['repair'] ) && 'delete' === $wg_data['repair'] && file_exists( $wg_issue['file'] ) ) : ?>
							<a class="button wg-danger wg-confirm-delete" href="<?php echo esc_url( Admin::actionUrl( 'issue', array( 'id' => $wg_issue['id'], 'op' => 'delete' ) ) ); ?>"><?php esc_html_e( 'Delete file', 'wordgate' ); ?></a>
						<?php endif; ?>
						<?php if ( in_array( $wg_issue['type'], array( 'core_update', 'plugin_update', 'theme_update', 'vulnerable_plugin', 'vulnerable_theme' ), true ) ) : ?>
							<a class="button button-primary" href="<?php echo esc_url( admin_url( 'update-core.php' ) ); ?>"><?php esc_html_e( 'Go to updates', 'wordgate' ); ?></a>
						<?php endif; ?>
						<?php
						$wg_is_admin_issue = in_array( $wg_issue['type'], array( 'suspicious_admin', 'admin_added', 'admin_no_role', 'suspicious_admin_name', 'hidden_admin_user' ), true );
						if ( $wg_is_admin_issue && ! empty( $wg_data['user_id'] ) ) :
							?>
							<a class="button button-primary" href="<?php echo esc_url( get_edit_user_link( (int) $wg_data['user_id'] ) ); ?>"><?php esc_html_e( 'View user', 'wordgate' ); ?></a>
						<?php endif; ?>
						<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'issue', array( 'id' => $wg_issue['id'], 'op' => 'ignore' ) ) ); ?>"><?php echo $wg_is_admin_issue ? esc_html__( 'Trust this user', 'wordgate' ) : esc_html__( 'Ignore', 'wordgate' ); ?></a>
					<?php elseif ( 'ignored' === $wg_issue['status'] ) : ?>
						<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'issue', array( 'id' => $wg_issue['id'], 'op' => 'unignore' ) ) ); ?>"><?php esc_html_e( 'Stop ignoring', 'wordgate' ); ?></a>
					<?php endif; ?>
				</p>
			</div>
		</details>
	<?php endforeach; ?>
	</div>
<?php endif; ?>

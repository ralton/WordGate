<?php
/**
 * IP blocking view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Plugin;

defined( 'ABSPATH' ) || exit;

$wg_blocks = Plugin::storage()->getBlocks();
uasort(
	$wg_blocks,
	static function ( $a, $b ) {
		return $b['created'] - $a['created'];
	}
);
$wg_sources = array(
	'manual'      => __( 'Manual', 'wordgate' ),
	'brute_force' => __( 'Brute force', 'wordgate' ),
	'rate_limit'  => __( 'Rate limit', 'wordgate' ),
	'404_limit'   => __( '404 scanning', 'wordgate' ),
	'cli'         => 'WP-CLI',
);
?>
<div class="wg-panel">
	<h2><?php esc_html_e( 'Block an IP address or range', 'wordgate' ); ?></h2>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wg-inline-form">
		<input type="hidden" name="action" value="wordgate_block" />
		<?php wp_nonce_field( 'wordgate_block' ); ?>
		<input type="text" name="ip" placeholder="203.0.113.7 or 203.0.113.0/24" class="regular-text code" required />
		<input type="text" name="reason" placeholder="<?php esc_attr_e( 'Reason (optional)', 'wordgate' ); ?>" class="regular-text" />
		<select name="minutes">
			<option value="60"><?php esc_html_e( '1 hour', 'wordgate' ); ?></option>
			<option value="1440"><?php esc_html_e( '1 day', 'wordgate' ); ?></option>
			<option value="10080"><?php esc_html_e( '1 week', 'wordgate' ); ?></option>
			<option value="43200"><?php esc_html_e( '30 days', 'wordgate' ); ?></option>
			<option value="0" selected><?php esc_html_e( 'Permanent', 'wordgate' ); ?></option>
		</select>
		<select name="scope">
			<option value="all"><?php esc_html_e( 'Entire site', 'wordgate' ); ?></option>
			<option value="login"><?php esc_html_e( 'Login only', 'wordgate' ); ?></option>
		</select>
		<?php submit_button( __( 'Block', 'wordgate' ), 'primary', 'submit', false ); ?>
	</form>
	<p class="description"><?php echo esc_html( sprintf( __( 'Your IP: %s', 'wordgate' ), Plugin::clientIp() ) ); ?></p>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Active blocks', 'wordgate' ); ?></h2>
	<?php if ( ! $wg_blocks ) : ?>
		<p class="wg-empty"><?php esc_html_e( 'No IPs are blocked.', 'wordgate' ); ?></p>
	<?php else : ?>
		<table class="widefat striped">
			<thead><tr><th><?php esc_html_e( 'IP / range', 'wordgate' ); ?></th><th><?php esc_html_e( 'Reason', 'wordgate' ); ?></th><th><?php esc_html_e( 'Source', 'wordgate' ); ?></th><th><?php esc_html_e( 'Scope', 'wordgate' ); ?></th><th><?php esc_html_e( 'Blocked', 'wordgate' ); ?></th><th><?php esc_html_e( 'Expires', 'wordgate' ); ?></th><th></th></tr></thead>
			<tbody>
			<?php foreach ( $wg_blocks as $wg_ip => $wg_b ) : $wg_expired = ! empty( $wg_b['expires'] ) && $wg_b['expires'] < time(); ?>
				<tr class="<?php echo $wg_expired ? 'wg-muted' : ''; ?>">
					<td><code><?php echo esc_html( $wg_ip ); ?></code></td>
					<td><?php echo esc_html( $wg_b['reason'] ); ?></td>
					<td><?php echo esc_html( $wg_sources[ $wg_b['source'] ] ?? $wg_b['source'] ); ?></td>
					<td><?php echo 'login' === $wg_b['scope'] ? esc_html__( 'Login', 'wordgate' ) : esc_html__( 'Site', 'wordgate' ); ?></td>
					<td><?php echo esc_html( Admin::timeAgo( $wg_b['created'] ) ); ?></td>
					<td>
						<?php
						if ( empty( $wg_b['expires'] ) ) {
							esc_html_e( 'Never', 'wordgate' );
						} elseif ( $wg_expired ) {
							esc_html_e( 'Expired', 'wordgate' );
						} else {
							/* translators: %s: time */
							echo esc_html( sprintf( __( 'in %s', 'wordgate' ), human_time_diff( time(), $wg_b['expires'] ) ) );
						}
						?>
					</td>
					<td class="wg-right"><a href="<?php echo esc_url( Admin::actionUrl( 'unblock', array( 'ip' => $wg_ip ) ) ); ?>"><?php esc_html_e( 'Unblock', 'wordgate' ); ?></a></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>

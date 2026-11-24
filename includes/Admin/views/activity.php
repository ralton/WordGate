<?php
/**
 * Activity log view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Log\EventLog;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.Security.NonceVerification -- read-only filters.
$wg_args = array(
	'type'   => isset( $_GET['type'] ) ? sanitize_key( $_GET['type'] ) : '',
	'ip'     => isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '',
	'search' => isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '',
	'page'   => isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1,
);
// phpcs:enable
$wg_result = EventLog::query( $wg_args );
$wg_types  = array(
	''             => __( 'All events', 'wordgate' ),
	'waf_block'    => __( 'Firewall blocks', 'wordgate' ),
	'ip_blocked'   => __( 'Blocked IP requests', 'wordgate' ),
	'rate_limit'   => __( 'Rate limited', 'wordgate' ),
	'waf_learning' => __( 'Learning mode matches', 'wordgate' ),
	'login_failed'           => __( 'Failed logins', 'wordgate' ),
	'lockout'                => __( 'Lockouts', 'wordgate' ),
	'lostpassword_throttled' => __( 'Password resets throttled', 'wordgate' ),
	'2fa_failed'             => __( '2FA failures', 'wordgate' ),
	'2fa_success'  => __( '2FA logins', 'wordgate' ),
	'scan_finished' => __( 'Scans', 'wordgate' ),
);
$wg_pages = (int) ceil( $wg_result['total'] / 50 );
?>
<form method="get" class="wg-filters">
	<input type="hidden" name="page" value="wordgate-activity" />
	<select name="type">
		<?php foreach ( $wg_types as $wg_k => $wg_v ) : ?>
			<option value="<?php echo esc_attr( $wg_k ); ?>" <?php selected( $wg_args['type'], $wg_k ); ?>><?php echo esc_html( $wg_v ); ?></option>
		<?php endforeach; ?>
	</select>
	<input type="text" name="ip" value="<?php echo esc_attr( $wg_args['ip'] ); ?>" placeholder="<?php esc_attr_e( 'IP address', 'wordgate' ); ?>" />
	<input type="search" name="s" value="<?php echo esc_attr( $wg_args['search'] ); ?>" placeholder="<?php esc_attr_e( 'URL, user or reason', 'wordgate' ); ?>" />
	<?php submit_button( __( 'Filter', 'wordgate' ), 'secondary', '', false ); ?>
	<span class="wg-count"><?php echo esc_html( sprintf( _n( '%s event', '%s events', $wg_result['total'], 'wordgate' ), number_format_i18n( $wg_result['total'] ) ) ); ?></span>
</form>

<table class="widefat striped wg-log">
	<thead><tr><th><?php esc_html_e( 'Time', 'wordgate' ); ?></th><th><?php esc_html_e( 'Event', 'wordgate' ); ?></th><th><?php esc_html_e( 'IP', 'wordgate' ); ?></th><th><?php esc_html_e( 'Details', 'wordgate' ); ?></th><th></th></tr></thead>
	<tbody>
	<?php if ( ! $wg_result['rows'] ) : ?>
		<tr><td colspan="5" class="wg-empty"><?php esc_html_e( 'No events.', 'wordgate' ); ?></td></tr>
	<?php endif; ?>
	<?php foreach ( $wg_result['rows'] as $wg_row ) : $wg_det = json_decode( $wg_row['details'], true ); ?>
		<tr>
			<td title="<?php echo esc_attr( wp_date( 'Y-m-d H:i:s', $wg_row['created'] ) ); ?>"><?php echo esc_html( Admin::timeAgo( $wg_row['created'] ) ); ?></td>
			<td><span class="wg-type wg-type-<?php echo esc_attr( $wg_row['type'] ); ?>"><?php echo esc_html( $wg_types[ $wg_row['type'] ] ?? $wg_row['type'] ); ?></span></td>
			<td><?php if ( $wg_row['ip'] ) : ?><a href="<?php echo esc_url( add_query_arg( 'ip', $wg_row['ip'] ) ); ?>"><code><?php echo esc_html( $wg_row['ip'] ); ?></code></a><?php endif; ?></td>
			<td class="wg-log-details">
				<?php if ( $wg_row['reason'] ) : ?><strong><?php echo esc_html( $wg_row['reason'] ); ?></strong><br><?php endif; ?>
				<?php if ( $wg_row['user_login'] ) : ?><?php esc_html_e( 'User:', 'wordgate' ); ?> <code><?php echo esc_html( $wg_row['user_login'] ); ?></code><br><?php endif; ?>
				<?php if ( $wg_row['uri'] ) : ?><code class="wg-uri"><?php echo esc_html( $wg_row['method'] . ' ' . $wg_row['uri'] ); ?></code><br><?php endif; ?>
				<?php if ( ! empty( $wg_det['match'] ) ) : ?><small><?php echo esc_html( sprintf( '%s.%s: %s', $wg_det['match']['target'], $wg_det['match']['param'], $wg_det['match']['matched'] ) ); ?></small><?php endif; ?>
			</td>
			<td class="wg-right">
				<?php if ( ! empty( $wg_det['match'] ) && $wg_row['rule_id'] ) : ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-firewall&rule_id=' . (int) $wg_row['rule_id'] . '&param=' . rawurlencode( $wg_det['match']['target'] . '.' . $wg_det['match']['param'] ) . '&path=' . rawurlencode( '^' . preg_quote( (string) wp_parse_url( $wg_row['uri'], PHP_URL_PATH ), '#' ) . '$' ) . '#wg-allow-form' ) ); ?>" title="<?php esc_attr_e( 'Mark as false positive', 'wordgate' ); ?>"><?php esc_html_e( 'Allowlist', 'wordgate' ); ?></a>
				<?php endif; ?>
			</td>
		</tr>
	<?php endforeach; ?>
	</tbody>
</table>
<?php if ( $wg_pages > 1 ) : ?>
	<div class="tablenav"><div class="tablenav-pages">
		<?php
		echo wp_kses_post(
			paginate_links(
				array(
					'base'    => add_query_arg( 'paged', '%#%' ),
					'format'  => '',
					'current' => $wg_args['page'],
					'total'   => $wg_pages,
				)
			)
		);
		?>
	</div></div>
<?php endif; ?>

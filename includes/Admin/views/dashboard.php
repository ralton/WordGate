<?php
/**
 * Dashboard view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Firewall\WafInstaller;
use WordGate\Log\EventLog;
use WordGate\Login\TwoFactor;
use WordGate\Scanner\Issues;
use WordGate\Settings;

defined( 'ABSPATH' ) || exit;

$wg_waf     = WafInstaller::status();
$wg_mode    = Settings::get( 'waf_mode' );
$wg_week    = EventLog::stats( time() - 14 * DAY_IN_SECONDS );
$wg_day     = EventLog::stats( time() - DAY_IN_SECONDS );
$wg_counts  = Issues::counts();
$wg_last    = get_option( 'wordgate_last_scan' );
$wg_blocked = static function ( $s ) {
	$t = $s['by_type'];
	return (int) ( ( $t['waf_block'] ?? 0 ) + ( $t['ip_blocked'] ?? 0 ) + ( $t['rate_limit'] ?? 0 ) );
};
$wg_admins  = get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) );
$wg_2fa     = count( array_filter( $wg_admins, static function ( $u ) { return TwoFactor::isEnabled( $u->ID ); } ) );
$wg_blocks  = WordGate\Plugin::storage()->getBlocks();
$wg_active  = count( array_filter( $wg_blocks, static function ( $b ) { return empty( $b['expires'] ) || $b['expires'] > time(); } ) );

$wg_fw_state = 'disabled' === $wg_mode ? 'bad' : ( 'learning' === $wg_mode || 'basic' !== $wg_waf['mode'] && 'extended' !== $wg_waf['mode'] ? 'warn' : 'good' );
?>
<div class="wg-cards">
	<div class="wg-card wg-<?php echo esc_attr( $wg_fw_state ); ?>">
		<h3><?php esc_html_e( 'Firewall', 'wordgate' ); ?></h3>
		<p class="wg-big">
			<?php
			if ( 'disabled' === $wg_mode ) {
				esc_html_e( 'Disabled', 'wordgate' );
			} elseif ( 'learning' === $wg_mode ) {
				esc_html_e( 'Learning mode', 'wordgate' );
			} else {
				esc_html_e( 'Active', 'wordgate' );
			}
			?>
		</p>
		<p>
			<?php
			$wg_labels = array(
				'extended' => __( 'Extended protection (runs before WordPress)', 'wordgate' ),
				'basic'    => __( 'Basic protection (must-use plugin)', 'wordgate' ),
				'none'     => __( 'Loader not installed — running late', 'wordgate' ),
			);
			echo esc_html( $wg_labels[ $wg_waf['mode'] ] );
			?>
		</p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-firewall' ) ); ?>"><?php esc_html_e( 'Manage firewall →', 'wordgate' ); ?></a>
	</div>

	<div class="wg-card">
		<h3><?php esc_html_e( 'Attacks blocked', 'wordgate' ); ?></h3>
		<p class="wg-big"><?php echo esc_html( number_format_i18n( $wg_blocked( $wg_day ) ) ); ?> <small><?php esc_html_e( 'last 24h', 'wordgate' ); ?></small></p>
		<p><?php echo esc_html( sprintf( __( '%1$s in 14 days · %2$s IPs blocked now', 'wordgate' ), number_format_i18n( $wg_blocked( $wg_week ) ), number_format_i18n( $wg_active ) ) ); ?></p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-activity' ) ); ?>"><?php esc_html_e( 'View activity →', 'wordgate' ); ?></a>
	</div>

	<div class="wg-card wg-<?php echo $wg_counts['critical'] ? 'bad' : ( $wg_counts['high'] || ! $wg_last ? 'warn' : 'good' ); ?>">
		<h3><?php esc_html_e( 'Scan', 'wordgate' ); ?></h3>
		<p class="wg-big"><?php echo esc_html( sprintf( _n( '%d open issue', '%d open issues', $wg_counts['open'], 'wordgate' ), $wg_counts['open'] ) ); ?></p>
		<p>
			<?php
			echo $wg_last
				? esc_html( sprintf( __( 'Last scan %1$s · %2$d critical, %3$d high', 'wordgate' ), Admin::timeAgo( $wg_last['finished'] ), $wg_counts['critical'], $wg_counts['high'] ) )
				: esc_html__( 'No scan has run yet.', 'wordgate' );
			?>
		</p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-scan' ) ); ?>"><?php esc_html_e( 'Open scanner →', 'wordgate' ); ?></a>
	</div>

	<div class="wg-card wg-<?php echo count( $wg_admins ) === $wg_2fa ? 'good' : 'warn'; ?>">
		<h3><?php esc_html_e( 'Login security', 'wordgate' ); ?></h3>
		<p class="wg-big"><?php echo esc_html( sprintf( __( '%1$d / %2$d admins', 'wordgate' ), $wg_2fa, count( $wg_admins ) ) ); ?> <small><?php esc_html_e( 'use 2FA', 'wordgate' ); ?></small></p>
		<p><?php echo esc_html( sprintf( __( '%1$s failed logins · %2$s lockouts (14 days)', 'wordgate' ), number_format_i18n( $wg_week['by_type']['login_failed'] ?? 0 ), number_format_i18n( $wg_week['by_type']['lockout'] ?? 0 ) ) ); ?></p>
		<a href="<?php echo esc_url( admin_url( 'profile.php#wordgate-2fa' ) ); ?>"><?php esc_html_e( 'Set up your 2FA →', 'wordgate' ); ?></a>
	</div>
</div>

<div class="wg-grid">
	<div class="wg-panel">
		<h2><?php esc_html_e( 'Blocked requests — last 14 days', 'wordgate' ); ?></h2>
		<?php
		$wg_max   = max( 1, max( array_map( 'intval', $wg_week['daily'] ?: array( 0 ) ) ) );
		$wg_today = (int) floor( time() / DAY_IN_SECONDS );
		echo '<div class="wg-bars" role="img" aria-label="' . esc_attr__( 'Daily blocked requests', 'wordgate' ) . '">';
		for ( $wg_d = $wg_today - 13; $wg_d <= $wg_today; $wg_d++ ) {
			$wg_n = (int) ( $wg_week['daily'][ $wg_d ] ?? 0 );
			printf(
				'<div class="wg-bar" title="%1$s: %2$d"><span style="height:%3$d%%"></span><em>%4$s</em></div>',
				esc_attr( wp_date( get_option( 'date_format' ), $wg_d * DAY_IN_SECONDS ) ),
				(int) $wg_n,
				(int) round( $wg_n / $wg_max * 100 ),
				esc_html( wp_date( 'j', $wg_d * DAY_IN_SECONDS ) )
			);
		}
		echo '</div>';
		?>
	</div>

	<div class="wg-panel">
		<h2><?php esc_html_e( 'Top attacking IPs (14 days)', 'wordgate' ); ?></h2>
		<?php if ( empty( $wg_week['top_ips'] ) ) : ?>
			<p class="wg-empty"><?php esc_html_e( 'Nothing yet. Quiet is good.', 'wordgate' ); ?></p>
		<?php else : ?>
			<table class="widefat striped"><tbody>
			<?php foreach ( $wg_week['top_ips'] as $wg_row ) : ?>
				<tr>
					<td><code><?php echo esc_html( $wg_row['ip'] ); ?></code></td>
					<td><?php echo esc_html( number_format_i18n( $wg_row['n'] ) ); ?></td>
					<td class="wg-right"><a href="<?php echo esc_url( admin_url( 'admin.php?page=wordgate-activity&ip=' . rawurlencode( $wg_row['ip'] ) ) ); ?>"><?php esc_html_e( 'Details', 'wordgate' ); ?></a></td>
				</tr>
			<?php endforeach; ?>
			</tbody></table>
		<?php endif; ?>
	</div>

	<div class="wg-panel">
		<h2><?php esc_html_e( 'Top firewall rules (14 days)', 'wordgate' ); ?></h2>
		<?php if ( empty( $wg_week['top_rules'] ) ) : ?>
			<p class="wg-empty"><?php esc_html_e( 'No rule matches yet.', 'wordgate' ); ?></p>
		<?php else : ?>
			<table class="widefat striped"><tbody>
			<?php foreach ( $wg_week['top_rules'] as $wg_row ) : ?>
				<tr><td><code><?php echo (int) $wg_row['rule_id']; ?></code> <?php echo esc_html( $wg_row['reason'] ); ?></td><td class="wg-right"><?php echo esc_html( number_format_i18n( $wg_row['n'] ) ); ?></td></tr>
			<?php endforeach; ?>
			</tbody></table>
		<?php endif; ?>
	</div>
</div>

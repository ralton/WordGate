<?php
/**
 * Login security view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Login\TwoFactor;

defined( 'ABSPATH' ) || exit;

$wg_users = get_users(
	array(
		'role__in' => array( 'administrator', 'editor', 'shop_manager' ),
		'fields'   => array( 'ID', 'user_login', 'display_name' ),
	)
);
?>
<div class="wg-panel">
	<h2><?php esc_html_e( 'Brute-force protection', 'wordgate' ); ?></h2>
	<?php Admin::formStart( 'login' ); ?>
	<table class="form-table" role="presentation">
		<?php
		Admin::checkbox( 'bf_enabled', __( 'Lock out repeated failures', 'wordgate' ) );
		Admin::number( 'bf_max_failures', __( 'Failed attempts allowed', 'wordgate' ), '', __( 'per IP', 'wordgate' ) );
		Admin::number( 'bf_window_minutes', __( 'Counted within', 'wordgate' ), '', __( 'minutes', 'wordgate' ) );
		Admin::number( 'bf_lockout_minutes', __( 'Lockout duration', 'wordgate' ), __( 'Locked-out IPs can still browse the site; only login and XML-RPC are blocked.', 'wordgate' ), __( 'minutes', 'wordgate' ) );
		Admin::number( 'bf_max_password_resets', __( 'Password reset limit', 'wordgate' ), __( 'Maximum lost-password requests per IP (and per account) per hour before locking out the IP. 0 disables. Reset requests always show a generic confirmation whether or not the account exists.', 'wordgate' ), __( 'per hour', 'wordgate' ) );
		Admin::checkbox( 'bf_invalid_username_lockout', __( 'Instant lockout for unknown usernames', 'wordgate' ), __( 'Lock out on the first attempt with a username that does not exist. Very effective against bots, but may lock out real users who mistype and can reveal whether a username exists despite generic login errors.', 'wordgate' ) );
		Admin::textarea( 'bf_banned_usernames', __( 'Banned usernames', 'wordgate' ), __( 'Any login attempt with one of these (if no such user exists) causes an immediate lockout. One per line. Note: because existing accounts are not immediately locked out, this can reveal whether a listed username exists.', 'wordgate' ) );
		Admin::checkbox( 'generic_login_errors', __( 'Generic login errors', 'wordgate' ), __( 'Do not reveal whether the username or the password was wrong.', 'wordgate' ) );
		?>
	</table>
	<h2><?php esc_html_e( 'Two-factor authentication', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::roles( 'tfa_required_roles', __( 'Require 2FA for', 'wordgate' ), __( 'Users with these roles are asked to set up 2FA. After the grace period they can only access their profile until they do. Users always set up 2FA themselves from their profile page.', 'wordgate' ) );
		Admin::number( 'tfa_grace_days', __( 'Grace period', 'wordgate' ), '', __( 'days', 'wordgate' ) );
		?>
	</table>
	<h2><?php esc_html_e( 'Breached & common passwords', 'wordgate' ); ?></h2>
	<table class="form-table" role="presentation">
		<?php
		Admin::checkbox( 'pw_guard_enabled', __( 'Check for breached & common passwords', 'wordgate' ), __( 'Checks passwords on login, profile update, password reset, registration and WooCommerce account forms against a bundled common-password list.', 'wordgate' ) );
		Admin::checkbox( 'pw_hibp_enabled', __( 'Check Have I Been Pwned (k-anonymity)', 'wordgate' ), __( 'Sends only the first 5 characters of the SHA-1 hash (with padding) to api.pwnedpasswords.com — never the password or full hash. Fails open if unreachable. Turn off for local-only checks.', 'wordgate' ) );
		Admin::roles( 'pw_enforce_roles', __( 'Block & force reset for', 'wordgate' ), __( 'Selected roles cannot save a breached password and must change it after logging in. Other roles receive a warning.', 'wordgate' ) );
		?>
	</table>
	<?php Admin::formEnd(); ?>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Privileged users', 'wordgate' ); ?></h2>
	<table class="widefat striped">
		<thead><tr><th><?php esc_html_e( 'User', 'wordgate' ); ?></th><th><?php esc_html_e( 'Two-factor', 'wordgate' ); ?></th><th></th></tr></thead>
		<tbody>
		<?php foreach ( $wg_users as $wg_u ) : $wg_on = TwoFactor::isEnabled( $wg_u->ID ); ?>
			<tr>
				<td><strong><?php echo esc_html( $wg_u->display_name ); ?></strong> <code><?php echo esc_html( $wg_u->user_login ); ?></code></td>
				<td><?php echo $wg_on ? '<span class="wg-ok">✓ ' . esc_html__( 'Enabled', 'wordgate' ) . '</span>' : '<span class="wg-warn-text">' . esc_html__( 'Not enabled', 'wordgate' ) . '</span>'; ?></td>
				<td class="wg-right"><a href="<?php echo esc_url( get_current_user_id() === (int) $wg_u->ID ? admin_url( 'profile.php#wordgate-2fa' ) : get_edit_user_link( $wg_u->ID ) . '#wordgate-2fa' ); ?>"><?php esc_html_e( 'Manage', 'wordgate' ); ?></a></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	<p class="description"><?php echo wp_kses_post( __( 'Lost your phone and your recovery codes? Run <code>wp wordgate 2fa reset &lt;user&gt;</code> from the server, or define <code>WORDGATE_DISABLE_2FA</code> as true in wp-config.php temporarily.', 'wordgate' ) ); ?></p>
</div>

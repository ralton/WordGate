<?php
/**
 * Firewall view.
 *
 * @package WordGate
 */

use WordGate\Admin\Admin;
use WordGate\Firewall\WafConfig;
use WordGate\Firewall\WafInstaller;
use WordGate\Plugin;
use WordGate\Settings;

defined( 'ABSPATH' ) || exit;

$wg_status   = WafInstaller::status();
$wg_server   = WafInstaller::detectServer();
$wg_rules    = WafConfig::rules();
$wg_disabled = array_map( 'intval', (array) Settings::get( 'disabled_rules' ) );
$wg_servers  = array(
	'apache-mod_php' => __( 'Apache + mod_php (.htaccess)', 'wordgate' ),
	'litespeed'      => __( 'LiteSpeed (.htaccess)', 'wordgate' ),
	'user-ini'       => __( 'PHP-FPM / CGI, e.g. Nginx (.user.ini)', 'wordgate' ),
	'manual'         => __( 'I will edit php.ini myself', 'wordgate' ),
);
?>
<div class="wg-panel">
	<h2><?php esc_html_e( 'Protection level', 'wordgate' ); ?></h2>
	<?php if ( 'extended' === $wg_status['mode'] ) : ?>
		<p class="wg-ok"><span class="dashicons dashicons-yes-alt"></span> <strong><?php esc_html_e( 'Extended protection is active.', 'wordgate' ); ?></strong> <?php esc_html_e( 'The firewall runs before WordPress and before any PHP file — including vulnerable plugin files attacked directly.', 'wordgate' ); ?></p>
		<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'remove_extended' ) ) ); ?>"><?php esc_html_e( 'Switch back to basic protection', 'wordgate' ); ?></a>
	<?php else : ?>
		<?php if ( 'basic' === $wg_status['mode'] ) : ?>
			<p class="wg-warn-text"><span class="dashicons dashicons-info"></span> <strong><?php esc_html_e( 'Basic protection is active.', 'wordgate' ); ?></strong> <?php esc_html_e( 'The firewall runs as a must-use plugin: before other plugins, but only for requests that load WordPress.', 'wordgate' ); ?></p>
		<?php else : ?>
			<p class="wg-bad-text"><span class="dashicons dashicons-warning"></span> <strong><?php esc_html_e( 'The firewall loader is not installed.', 'wordgate' ); ?></strong> <?php esc_html_e( 'WordGate falls back to running inside the plugin, after other plugins have loaded.', 'wordgate' ); ?>
			<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'basic' ) ) ); ?>"><?php esc_html_e( 'Install basic protection', 'wordgate' ); ?></a></p>
		<?php endif; ?>

		<?php if ( $wg_status['conflict'] ) : ?>
			<p class="wg-bad-text"><?php echo esc_html( sprintf( __( 'Another auto_prepend_file is configured (%s). Extended protection cannot be set up automatically.', 'wordgate' ), $wg_status['prepend'] ) ); ?></p>
		<?php else : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wg-inline-form">
				<input type="hidden" name="action" value="wordgate_waf" /><input type="hidden" name="op" value="extended" />
				<?php wp_nonce_field( 'wordgate_waf' ); ?>
				<label for="wg-server"><strong><?php esc_html_e( 'Upgrade to extended protection:', 'wordgate' ); ?></strong></label>
				<select name="server" id="wg-server">
					<?php foreach ( $wg_servers as $wg_k => $wg_v ) : ?>
						<option value="<?php echo esc_attr( $wg_k ); ?>" <?php selected( $wg_server, $wg_k ); ?>><?php echo esc_html( $wg_v . ( $wg_k === $wg_server ? ' — ' . __( 'detected', 'wordgate' ) : '' ) ); ?></option>
					<?php endforeach; ?>
				</select>
				<?php submit_button( __( 'Set up', 'wordgate' ), 'primary', 'submit', false ); ?>
			</form>
			<details><summary><?php esc_html_e( 'Manual setup', 'wordgate' ); ?></summary>
				<p><?php esc_html_e( 'Add this line to your php.ini (or ask your host to), then reload PHP:', 'wordgate' ); ?></p>
				<pre class="wg-code">auto_prepend_file = '<?php echo esc_html( WafInstaller::stubPath() ); ?>'</pre>
				<p><?php esc_html_e( 'Click "Set up" with "I will edit php.ini myself" first so the loader file exists.', 'wordgate' ); ?></p>
			</details>
		<?php endif; ?>
	<?php endif; ?>
	<?php
	$wg_sw = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
	if ( 'user-ini' === $wg_server || false !== strpos( $wg_sw, 'nginx' ) ) :
		?>
		<details><summary><?php esc_html_e( 'Nginx configuration (block web access to data files and .user.ini)', 'wordgate' ); ?></summary>
			<p><?php esc_html_e( 'Nginx ignores .htaccess files. Add this block to your site\'s server {} config so logs and .user.ini cannot be downloaded:', 'wordgate' ); ?></p>
			<pre class="wg-code"><?php echo esc_html( WafInstaller::nginxSnippet() ); ?></pre>
		</details>
	<?php endif; ?>
	<p class="description"><?php echo wp_kses_post( sprintf( __( 'Emergency off switch: create an empty file named %1$s in %2$s, or add %3$s to wp-config.php.', 'wordgate' ), '<code>disable-waf</code>', '<code>' . esc_html( WORDGATE_DATA_DIR ) . '</code>', "<code>define( 'WORDGATE_WAF_DISABLE', true );</code>" ) ); ?></p>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Disable PHP execution in uploads', 'wordgate' ); ?></h2>
	<?php $wg_uploads_protected = WafInstaller::isUploadsPhpDisabled(); ?>
	<?php if ( $wg_uploads_protected ) : ?>
		<p class="wg-ok"><span class="dashicons dashicons-yes-alt"></span> <strong><?php esc_html_e( 'Uploads .htaccess rule is installed.', 'wordgate' ); ?></strong> <?php esc_html_e( 'Apache / LiteSpeed will deny direct requests to PHP files inside wp-content/uploads/ before PHP runs.', 'wordgate' ); ?></p>
		<p>
			<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'uploads_test' ) ) ); ?>"><?php esc_html_e( 'Test PHP execution now', 'wordgate' ); ?></a>
			<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'uploads_disable' ) ) ); ?>"><?php esc_html_e( 'Remove .htaccess rule', 'wordgate' ); ?></a>
		</p>
	<?php else : ?>
		<p><?php esc_html_e( 'Uploaded PHP backdoors are the most common persistence method. Blocking PHP execution in wp-content/uploads/ at the web server adds defence in depth alongside WAF rule 6003.', 'wordgate' ); ?></p>
		<p>
			<a class="button button-primary" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'uploads_enable' ) ) ); ?>"><?php esc_html_e( 'Disable PHP execution in uploads', 'wordgate' ); ?></a>
			<a class="button" href="<?php echo esc_url( Admin::actionUrl( 'waf', array( 'op' => 'uploads_test' ) ) ); ?>"><?php esc_html_e( 'Test PHP execution now', 'wordgate' ); ?></a>
		</p>
	<?php endif; ?>
	<details><summary><?php esc_html_e( 'Nginx configuration (manual setup)', 'wordgate' ); ?></summary>
		<p><?php esc_html_e( 'Nginx ignores .htaccess files. Add this location block to your server {} config, then click "Test PHP execution now" above to verify:', 'wordgate' ); ?></p>
		<pre class="wg-code"><?php echo esc_html( WafInstaller::uploadsNginxSnippet() ); ?></pre>
	</details>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Firewall options', 'wordgate' ); ?></h2>
	<?php Admin::formStart( 'firewall' ); ?>
	<table class="form-table" role="presentation">
		<?php
		Admin::select(
			'waf_mode',
			__( 'Mode', 'wordgate' ),
			array(
				'enabled'  => __( 'Enabled — block attacks', 'wordgate' ),
				'learning' => __( 'Learning — log matches but do not block', 'wordgate' ),
				'disabled' => __( 'Disabled', 'wordgate' ),
			),
			__( 'Use learning mode for a few days on complex sites to spot false positives, then allowlist them below. IP blocks are enforced in every mode except Disabled.', 'wordgate' )
		);
		Admin::select(
			'ip_source',
			__( 'Client IP comes from', 'wordgate' ),
			array(
				'REMOTE_ADDR'           => 'REMOTE_ADDR ' . __( '(direct connection — default)', 'wordgate' ),
				'HTTP_X_FORWARDED_FOR'  => 'X-Forwarded-For',
				'HTTP_X_REAL_IP'        => 'X-Real-IP',
				'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP (Cloudflare)',
				'HTTP_TRUE_CLIENT_IP'   => 'True-Client-IP',
			),
			sprintf( __( 'Your IP as WordGate sees it: %s. Only change this if your site is behind a proxy or CDN, and list the proxy addresses below — otherwise attackers could fake their IP.', 'wordgate' ), '<code>' . esc_html( Plugin::clientIp() ) . '</code>' )
		);
		Admin::textarea( 'trusted_proxies', __( 'Trusted proxy IPs', 'wordgate' ), __( 'One IP or CIDR range per line. The header above is only trusted when the request comes from one of these.', 'wordgate' ), "173.245.48.0/20\n103.21.244.0/22" );
		Admin::textarea( 'allowlist_ips', __( 'Allowlisted IPs', 'wordgate' ), __( 'These IPs bypass the firewall, rate limits and login lockouts entirely. One IP or CIDR per line.', 'wordgate' ) );
		Admin::checkbox( 'rate_limit_enabled', __( 'Rate limiting', 'wordgate' ), __( 'Limit how many PHP requests a single IP can make per minute. Static files are not counted.', 'wordgate' ) );
		Admin::number( 'rate_limit_rpm', __( 'Requests per minute', 'wordgate' ), __( 'Per IP. 240 is generous for humans; aggressive crawlers exceed it.', 'wordgate' ) );
		Admin::select(
			'rate_limit_action',
			__( 'When exceeded', 'wordgate' ),
			array(
				'throttle' => __( 'Throttle (HTTP 429 until the minute is over)', 'wordgate' ),
				'block'    => __( 'Block the IP temporarily', 'wordgate' ),
			)
		);
		Admin::number( 'rate_limit_block_minutes', __( 'Temporary block duration', 'wordgate' ), '', __( 'minutes', 'wordgate' ) );
		Admin::number( 'not_found_limit', __( '404 limit', 'wordgate' ), __( 'Block anonymous IPs that trigger more than this many "not found" pages per minute (vulnerability scanners). 0 disables. 30 is a sensible value.', 'wordgate' ), __( 'per minute', 'wordgate' ) );
		Admin::checkbox( 'block_page_show_reason', __( 'Show reason on block page', 'wordgate' ), __( 'Helps when debugging false positives; leave off in production to avoid giving attackers hints.', 'wordgate' ) );
		?>
	</table>
	<?php Admin::formEnd(); ?>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'Rules', 'wordgate' ); ?> <small>(<?php echo count( $wg_rules ); ?>)</small></h2>
	<p class="description"><?php echo wp_kses_post( __( 'Rules are open source and community maintained. Rules marked <em>admin bypass</em> are skipped for logged-in users who may already publish unfiltered HTML.', 'wordgate' ) ); ?></p>
	<table class="widefat striped wg-rules">
		<thead><tr><th>ID</th><th><?php esc_html_e( 'Rule', 'wordgate' ); ?></th><th><?php esc_html_e( 'Category', 'wordgate' ); ?></th><th><?php esc_html_e( 'Severity', 'wordgate' ); ?></th><th><?php esc_html_e( 'Status', 'wordgate' ); ?></th><th></th></tr></thead>
		<tbody>
		<?php foreach ( $wg_rules as $wg_rule ) : $wg_off = in_array( $wg_rule->id, $wg_disabled, true ); ?>
			<tr class="<?php echo $wg_off ? 'wg-muted' : ''; ?>">
				<td><code><?php echo (int) $wg_rule->id; ?></code></td>
				<td><?php echo esc_html( $wg_rule->name ); ?><?php echo $wg_rule->adminBypass ? ' <em class="wg-tag">admin bypass</em>' : ''; ?><?php echo 'log' === $wg_rule->action ? ' <em class="wg-tag">log only</em>' : ''; ?></td>
				<td><?php echo esc_html( $wg_rule->category ); ?></td>
				<td><?php echo Admin::severityBadge( $wg_rule->severity ); // phpcs:ignore ?></td>
				<td><?php echo $wg_off ? esc_html__( 'Disabled', 'wordgate' ) : esc_html__( 'Active', 'wordgate' ); ?></td>
				<td class="wg-right"><a href="<?php echo esc_url( Admin::actionUrl( 'rule', array( 'rule' => $wg_rule->id ) ) ); ?>"><?php echo $wg_off ? esc_html__( 'Enable', 'wordgate' ) : esc_html__( 'Disable', 'wordgate' ); ?></a></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>

<div class="wg-panel">
	<h2><?php esc_html_e( 'False-positive allowlist', 'wordgate' ); ?></h2>
	<p class="description"><?php esc_html_e( 'Skip a rule for a specific URL path and/or parameter instead of disabling it everywhere. Tip: use "Allowlist" on an entry in the Activity Log to pre-fill this form.', 'wordgate' ); ?></p>
	<?php $wg_allow = (array) Settings::get( 'allow_rules' ); ?>
	<?php if ( $wg_allow ) : ?>
		<table class="widefat striped"><thead><tr><th><?php esc_html_e( 'Rule', 'wordgate' ); ?></th><th><?php esc_html_e( 'Path (regex)', 'wordgate' ); ?></th><th><?php esc_html_e( 'Parameter', 'wordgate' ); ?></th><th></th></tr></thead><tbody>
		<?php foreach ( $wg_allow as $wg_i => $wg_a ) : ?>
			<tr><td><?php echo $wg_a['rule_id'] ? '<code>' . (int) $wg_a['rule_id'] . '</code>' : esc_html__( 'Any', 'wordgate' ); ?></td><td><code><?php echo esc_html( $wg_a['path'] ? $wg_a['path'] : '*' ); ?></code></td><td><code><?php echo esc_html( $wg_a['param'] ? $wg_a['param'] : '*' ); ?></code></td>
			<td class="wg-right"><a href="<?php echo esc_url( Admin::actionUrl( 'allow_rule', array( 'remove' => $wg_i ) ) ); ?>"><?php esc_html_e( 'Remove', 'wordgate' ); ?></a></td></tr>
		<?php endforeach; ?>
		</tbody></table>
	<?php endif; ?>
	<?php
	// phpcs:disable WordPress.Security.NonceVerification -- prefill only.
	$wg_pre_rule  = isset( $_GET['rule_id'] ) ? (int) $_GET['rule_id'] : '';
	$wg_pre_path  = isset( $_GET['path'] ) ? sanitize_text_field( wp_unslash( $_GET['path'] ) ) : '';
	$wg_pre_param = isset( $_GET['param'] ) ? sanitize_text_field( wp_unslash( $_GET['param'] ) ) : '';
	// phpcs:enable
	?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wg-inline-form" id="wg-allow-form">
		<input type="hidden" name="action" value="wordgate_allow_rule" />
		<?php wp_nonce_field( 'wordgate_allow_rule' ); ?>
		<input type="number" name="rule_id" placeholder="<?php esc_attr_e( 'Rule ID (0 = any)', 'wordgate' ); ?>" value="<?php echo esc_attr( $wg_pre_rule ); ?>" class="small-text" style="width:140px" />
		<input type="text" name="path" placeholder="^/wp-admin/admin-ajax\.php$" value="<?php echo esc_attr( $wg_pre_path ); ?>" class="regular-text code" />
		<input type="text" name="param" placeholder="body.message" value="<?php echo esc_attr( $wg_pre_param ); ?>" class="regular-text code" />
		<?php submit_button( __( 'Add', 'wordgate' ), 'secondary', 'submit', false ); ?>
	</form>
</div>

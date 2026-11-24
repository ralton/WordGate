<?php
/**
 * Admin screens and form handlers.
 *
 * @package WordGate
 */

namespace WordGate\Admin;

use WordGate\Firewall\WafConfig;
use WordGate\Firewall\WafInstaller;
use WordGate\Log\EventLog;
use WordGate\Plugin;
use WordGate\Scanner\Issues;
use WordGate\Scanner\Repair;
use WordGate\Settings;
use WordGate\Waf\IpUtil;

final class Admin {

	const CAP = 'manage_options';

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WORDGATE_FILE ), array( __CLASS__, 'actionLinks' ) );

		foreach ( array( 'save', 'block', 'unblock', 'waf', 'issue', 'rule', 'allow_rule' ) as $action ) {
			add_action( 'admin_post_wordgate_' . $action, array( __CLASS__, 'handle' . str_replace( '_', '', ucwords( $action, '_' ) ) ) );
		}
	}

	public static function pages() {
		return array(
			'wordgate'          => array( __( 'Dashboard', 'wordgate' ), 'dashboard' ),
			'wordgate-firewall' => array( __( 'Firewall', 'wordgate' ), 'firewall' ),
			'wordgate-blocking' => array( __( 'Blocking', 'wordgate' ), 'blocking' ),
			'wordgate-scan'     => array( __( 'Scan', 'wordgate' ), 'scan' ),
			'wordgate-login'    => array( __( 'Login Security', 'wordgate' ), 'login' ),
			'wordgate-activity' => array( __( 'Activity Log', 'wordgate' ), 'activity' ),
			'wordgate-settings' => array( __( 'Settings', 'wordgate' ), 'settings' ),
		);
	}

	public static function menu() {
		$counts = Issues::counts();
		$badge  = $counts['critical'] + $counts['high'];
		$title  = 'WordGate' . ( $badge ? ' <span class="awaiting-mod">' . (int) $badge . '</span>' : '' );
		add_menu_page( 'WordGate', $title, self::CAP, 'wordgate', array( __CLASS__, 'render' ), 'dashicons-shield', 80 );
		foreach ( self::pages() as $slug => $page ) {
			add_submenu_page( 'wordgate', $page[0] . ' ‹ WordGate', $page[0], self::CAP, $slug, array( __CLASS__, 'render' ) );
		}
	}

	public static function actionLinks( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'admin.php?page=wordgate-settings' ) ) . '">' . esc_html__( 'Settings', 'wordgate' ) . '</a>' );
		return $links;
	}

	public static function assets( $hook ) {
		if ( false === strpos( $hook, 'wordgate' ) ) {
			return;
		}
		wp_enqueue_style( 'wordgate-admin', WORDGATE_URL . 'assets/admin.css', array(), WORDGATE_VERSION );
		wp_enqueue_script( 'wordgate-admin', WORDGATE_URL . 'assets/admin.js', array(), WORDGATE_VERSION, true );
		wp_localize_script(
			'wordgate-admin',
			'WordGateAdmin',
			array(
				'ajax'      => admin_url( 'admin-ajax.php' ),
				'scanNonce' => wp_create_nonce( 'wordgate_scan' ),
				'i18n'      => array(
					'confirmDelete' => __( 'Delete this file permanently? Make sure you have a backup.', 'wordgate' ),
					'done'          => __( 'Scan complete. Reloading…', 'wordgate' ),
					'failed'        => __( 'The scan stopped unexpectedly. Check the notes below and try again.', 'wordgate' ),
					'files'         => __( 'files', 'wordgate' ),
					'issues'        => __( 'issues', 'wordgate' ),
				),
			)
		);
	}

	public static function render() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'wordgate' ) );
		}
		EventLog::ingest(); // Pull fresh WAF events so screens are current.

		$page  = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : 'wordgate'; // phpcs:ignore WordPress.Security.NonceVerification
		$pages = self::pages();
		if ( ! isset( $pages[ $page ] ) ) {
			$page = 'wordgate';
		}
		echo '<div class="wrap wordgate">';
		echo '<h1 class="wordgate-title"><span class="dashicons dashicons-shield"></span> WordGate <span class="wordgate-sep">/</span> ' . esc_html( $pages[ $page ][0] ) . '</h1>';
		echo '<nav class="nav-tab-wrapper wordgate-tabs">';
		foreach ( $pages as $slug => $p ) {
			printf( '<a href="%s" class="nav-tab%s">%s</a>', esc_url( admin_url( 'admin.php?page=' . $slug ) ), $slug === $page ? ' nav-tab-active' : '', esc_html( $p[0] ) );
		}
		echo '</nav>';
		include __DIR__ . '/views/' . $pages[ $page ][1] . '.php';
		echo '</div>';
	}

	public static function notices() {
		$screen = get_current_screen();
		if ( ! $screen || false === strpos( $screen->id, 'wordgate' ) ) {
			return;
		}
		$msg = get_transient( 'wordgate_notice_' . get_current_user_id() );
		if ( $msg ) {
			delete_transient( 'wordgate_notice_' . get_current_user_id() );
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $msg[0] ), esc_html( $msg[1] ) );
		}
		if ( ! is_writable( dirname( WORDGATE_DATA_DIR ) ) && ! is_dir( WORDGATE_DATA_DIR ) ) {
			echo '<div class="notice notice-error"><p>' . esc_html( sprintf( __( 'WordGate cannot create its data directory (%s). The firewall cannot store blocks or settings until this is fixed.', 'wordgate' ), WORDGATE_DATA_DIR ) ) . '</p></div>';
		}
	}

	/* ---------------------------------------------------------------------
	 * Form helpers used by the views
	 * ------------------------------------------------------------------- */

	public static function formStart( $section ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="wordgate_save" />';
		echo '<input type="hidden" name="section" value="' . esc_attr( $section ) . '" />';
		wp_nonce_field( 'wordgate_save' );
	}

	public static function formEnd( $label = null ) {
		submit_button( $label ? $label : __( 'Save changes', 'wordgate' ) );
		echo '</form>';
	}

	private static function fieldMarker( $key ) {
		echo '<input type="hidden" name="fields[]" value="' . esc_attr( $key ) . '" />';
	}

	public static function checkbox( $key, $label, $help = '' ) {
		self::fieldMarker( $key );
		printf(
			'<tr><th scope="row">%1$s</th><td><label><input type="checkbox" name="s[%2$s]" value="1" %3$s /> %4$s</label>%5$s</td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			checked( (bool) Settings::get( $key ), true, false ),
			esc_html__( 'Enabled', 'wordgate' ),
			$help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : ''
		);
	}

	public static function number( $key, $label, $help = '', $suffix = '' ) {
		self::fieldMarker( $key );
		printf(
			'<tr><th scope="row"><label for="wg-%2$s">%1$s</label></th><td><input type="number" min="0" class="small-text" id="wg-%2$s" name="s[%2$s]" value="%3$d" /> %4$s%5$s</td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			(int) Settings::get( $key ),
			esc_html( $suffix ),
			$help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : ''
		);
	}

	public static function select( $key, $label, array $options, $help = '' ) {
		self::fieldMarker( $key );
		$html = '';
		foreach ( $options as $value => $text ) {
			$html .= sprintf( '<option value="%s" %s>%s</option>', esc_attr( $value ), selected( Settings::get( $key ), $value, false ), esc_html( $text ) );
		}
		printf(
			'<tr><th scope="row"><label for="wg-%2$s">%1$s</label></th><td><select id="wg-%2$s" name="s[%2$s]">%3$s</select>%4$s</td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			$html, // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above.
			$help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : ''
		);
	}

	public static function textarea( $key, $label, $help = '', $placeholder = '' ) {
		self::fieldMarker( $key );
		printf(
			'<tr><th scope="row"><label for="wg-%2$s">%1$s</label></th><td><textarea id="wg-%2$s" name="s[%2$s]" rows="4" class="large-text code" placeholder="%4$s">%3$s</textarea>%5$s</td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			esc_textarea( (string) Settings::get( $key ) ),
			esc_attr( $placeholder ),
			$help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : ''
		);
	}

	public static function text( $key, $label, $help = '', $placeholder = '' ) {
		self::fieldMarker( $key );
		printf(
			'<tr><th scope="row"><label for="wg-%2$s">%1$s</label></th><td><input type="text" class="regular-text" id="wg-%2$s" name="s[%2$s]" value="%3$s" placeholder="%4$s" />%5$s</td></tr>',
			esc_html( $label ),
			esc_attr( $key ),
			esc_attr( (string) Settings::get( $key ) ),
			esc_attr( $placeholder ),
			$help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : ''
		);
	}

	public static function roles( $key, $label, $help = '' ) {
		self::fieldMarker( $key );
		$current = (array) Settings::get( $key );
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><fieldset>';
		foreach ( wp_roles()->get_names() as $role => $name ) {
			printf( '<label style="margin-right:16px"><input type="checkbox" name="s[%1$s][]" value="%2$s" %3$s /> %4$s</label>', esc_attr( $key ), esc_attr( $role ), checked( in_array( $role, $current, true ), true, false ), esc_html( translate_user_role( $name ) ) );
		}
		echo '</fieldset>' . ( $help ? '<p class="description">' . wp_kses_post( $help ) . '</p>' : '' ) . '</td></tr>';
	}

	public static function actionUrl( $action, array $args = array() ) {
		return wp_nonce_url( add_query_arg( array_merge( array( 'action' => 'wordgate_' . $action ), $args ), admin_url( 'admin-post.php' ) ), 'wordgate_' . $action );
	}

	public static function timeAgo( $ts ) {
		/* translators: %s: human time difference */
		return $ts ? sprintf( __( '%s ago', 'wordgate' ), human_time_diff( (int) $ts ) ) : '—';
	}

	public static function severityBadge( $severity ) {
		return '<span class="wg-sev wg-sev-' . esc_attr( $severity ) . '">' . esc_html( ucfirst( $severity ) ) . '</span>';
	}

	/* ---------------------------------------------------------------------
	 * Handlers
	 * ------------------------------------------------------------------- */

	private static function guard( $nonce_action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'wordgate' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $nonce_action );
	}

	private static function back( $type, $message, $page = null ) {
		set_transient( 'wordgate_notice_' . get_current_user_id(), array( $type, $message ), 60 );
		$url = $page ? admin_url( 'admin.php?page=' . $page ) : wp_get_referer();
		wp_safe_redirect( $url ? $url : admin_url( 'admin.php?page=wordgate' ) );
		exit;
	}

	public static function handleSave() {
		self::guard( 'wordgate_save' );
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Settings::sanitize() handles it.
		$fields   = isset( $_POST['fields'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['fields'] ) ) : array();
		$values   = isset( $_POST['s'] ) ? (array) wp_unslash( $_POST['s'] ) : array();
		// phpcs:enable
		$defaults = Settings::defaults();
		$changes  = array();
		foreach ( $fields as $key ) {
			if ( ! array_key_exists( $key, $defaults ) ) {
				continue;
			}
			if ( isset( $values[ $key ] ) ) {
				$changes[ $key ] = $values[ $key ];
			} elseif ( is_bool( $defaults[ $key ] ) ) {
				$changes[ $key ] = false; // Unchecked checkbox.
			} elseif ( is_array( $defaults[ $key ] ) ) {
				$changes[ $key ] = array();
			}
		}

		// Safety net: don't let an admin behind a proxy lock themselves out by
		// switching the IP source to a header their proxy doesn't send.
		if ( isset( $changes['ip_source'] ) && 'REMOTE_ADDR' !== $changes['ip_source'] && empty( $_SERVER[ $changes['ip_source'] ] ) ) {
			self::back( 'error', __( 'Your current request does not include that header, so WordGate kept using REMOTE_ADDR. Check your proxy configuration.', 'wordgate' ) );
		}

		Settings::update( $changes );
		if ( isset( $changes['scan_schedule'] ) ) {
			\WordGate\Installer::scheduleCron();
		}
		self::back( 'success', __( 'Settings saved.', 'wordgate' ) );
	}

	public static function handleBlock() {
		self::guard( 'wordgate_block' );
		$ip      = isset( $_POST['ip'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['ip'] ) ) ) : '';
		$reason  = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';
		$minutes = isset( $_POST['minutes'] ) ? absint( $_POST['minutes'] ) : 0;
		$scope   = isset( $_POST['scope'] ) && 'login' === $_POST['scope'] ? 'login' : 'all';

		if ( ! IpUtil::isValidRange( $ip ) ) {
			self::back( 'error', __( 'Enter a valid IP address or CIDR range (e.g. 203.0.113.7 or 203.0.113.0/24).', 'wordgate' ) );
		}
		if ( IpUtil::inRange( Plugin::clientIp(), $ip ) ) {
			self::back( 'error', __( 'That would block your own IP address. Refusing.', 'wordgate' ) );
		}
		Plugin::storage()->addBlock( $ip, '' !== $reason ? $reason : __( 'Manual block', 'wordgate' ), $minutes, $scope, 'manual' );
		EventLog::add( 'manual_block', $ip, array( 'reason' => $reason, 'user_login' => wp_get_current_user()->user_login ), 'info' );
		/* translators: %s: IP */
		self::back( 'success', sprintf( __( 'Blocked %s.', 'wordgate' ), $ip ) );
	}

	public static function handleUnblock() {
		self::guard( 'wordgate_unblock' );
		$ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		Plugin::storage()->removeBlock( $ip );
		EventLog::add( 'unblock', $ip, array( 'user_login' => wp_get_current_user()->user_login ) );
		/* translators: %s: IP */
		self::back( 'success', sprintf( __( 'Unblocked %s.', 'wordgate' ), $ip ) );
	}

	public static function handleWaf() {
		self::guard( 'wordgate_waf' );
		$op = isset( $_REQUEST['op'] ) ? sanitize_key( $_REQUEST['op'] ) : '';
		Plugin::storage()->ensureDir();
		WafConfig::sync();
		switch ( $op ) {
			case 'basic':
				$result = WafInstaller::installBasic();
				break;
			case 'extended':
				$server = isset( $_POST['server'] ) ? sanitize_key( $_POST['server'] ) : WafInstaller::detectServer();
				$server = in_array( $server, array( 'apache-mod_php', 'litespeed', 'user-ini', 'manual' ), true ) ? $server : 'manual';
				$result = WafInstaller::installBasic(); // Keep basic as a fallback while extended propagates.
				if ( true === $result ) {
					$result = WafInstaller::installExtended( $server );
				}
				break;
			case 'remove_extended':
				WafInstaller::uninstallExtended();
				$result = true;
				break;
			case 'uploads_enable':
				$result = WafInstaller::enableUploadsPhpProtection();
				if ( true === $result ) {
					Settings::update( array( 'disable_uploads_php' => true ) );
					$test = WafInstaller::testUploadsPhpExecution();
					$type = 'blocked_by_server' === $test['status'] ? 'success' : ( 'executed' === $test['status'] || 'error' === $test['status'] ? 'error' : 'warning' );
					self::back( $type, __( 'Uploads .htaccess rule added.', 'wordgate' ) . ' ' . $test['message'] );
				}
				break;
			case 'uploads_disable':
				WafInstaller::disableUploadsPhpProtection();
				Settings::update( array( 'disable_uploads_php' => false ) );
				self::back( 'success', __( 'Uploads PHP protection rule removed.', 'wordgate' ) );
				// No break needed after self::back() exits.
			case 'uploads_test':
				$test = WafInstaller::testUploadsPhpExecution();
				$type = 'blocked_by_server' === $test['status'] ? 'success' : ( 'executed' === $test['status'] || 'error' === $test['status'] ? 'error' : 'warning' );
				self::back( $type, $test['message'] );
				// No break needed after self::back() exits.
			default:
				$result = new \WP_Error( 'op', 'Unknown operation' );
		}
		if ( is_wp_error( $result ) ) {
			self::back( 'error', $result->get_error_message() );
		}
		self::back( 'success', 'extended' === $op ? __( 'Extended protection configured. It can take up to 5 minutes to take effect on some servers.', 'wordgate' ) : __( 'Firewall updated.', 'wordgate' ) );
	}

	public static function handleIssue() {
		self::guard( 'wordgate_issue' );
		$id    = isset( $_REQUEST['id'] ) ? absint( $_REQUEST['id'] ) : 0;
		$op    = isset( $_REQUEST['op'] ) ? sanitize_key( $_REQUEST['op'] ) : '';
		$issue = Issues::get( $id );
		if ( ! $issue ) {
			self::back( 'error', __( 'Issue not found.', 'wordgate' ) );
		}
		if ( 'ignore' === $op || 'unignore' === $op ) {
			Issues::setStatus( $id, 'ignore' === $op ? 'ignored' : 'open' );
			self::back( 'success', 'ignore' === $op ? __( 'Issue ignored. It will not be reported again unless it changes.', 'wordgate' ) : __( 'Issue restored.', 'wordgate' ) );
		}
		$result = Repair::apply( $issue, $op );
		if ( is_wp_error( $result ) ) {
			self::back( 'error', $result->get_error_message() );
		}
		EventLog::add( 'repair', Plugin::clientIp(), array( 'reason' => $op . ': ' . $issue['file'], 'user_login' => wp_get_current_user()->user_login ), 'info' );
		self::back( 'success', 'restore' === $op ? __( 'Original file restored.', 'wordgate' ) : __( 'File deleted.', 'wordgate' ) );
	}

	public static function handleRule() {
		self::guard( 'wordgate_rule' );
		$id       = isset( $_GET['rule'] ) ? (int) $_GET['rule'] : 0;
		$disabled = array_map( 'intval', (array) Settings::get( 'disabled_rules' ) );
		if ( in_array( $id, $disabled, true ) ) {
			$disabled = array_values( array_diff( $disabled, array( $id ) ) );
			$msg      = __( 'Rule enabled.', 'wordgate' );
		} else {
			$disabled[] = $id;
			$msg        = __( 'Rule disabled.', 'wordgate' );
		}
		Settings::update( array( 'disabled_rules' => $disabled ) );
		self::back( 'success', $msg );
	}

	public static function handleAllowRule() {
		self::guard( 'wordgate_allow_rule' );
		$rules = (array) Settings::get( 'allow_rules' );
		if ( isset( $_GET['remove'] ) ) {
			unset( $rules[ (int) $_GET['remove'] ] );
		} else {
			$rule_id = isset( $_REQUEST['rule_id'] ) ? (int) $_REQUEST['rule_id'] : 0;
			$path    = isset( $_REQUEST['path'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['path'] ) ) : '';
			$param   = isset( $_REQUEST['param'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['param'] ) ) : '';
			if ( '' !== $path && false === @preg_match( \WordGate\Waf\Rule::compile( $path ), '' ) ) { // phpcs:ignore
				self::back( 'error', __( 'The path pattern is not a valid regular expression.', 'wordgate' ) );
			}
			if ( 0 === $rule_id && '' === $path && '' === $param ) {
				self::back( 'error', __( 'An allow rule needs at least a rule, path or parameter.', 'wordgate' ) );
			}
			$rules[] = array(
				'rule_id' => $rule_id,
				'path'    => $path,
				'param'   => $param,
				'added'   => time(),
			);
		}
		Settings::update( array( 'allow_rules' => array_values( $rules ) ) );
		self::back( 'success', __( 'Allowlist updated.', 'wordgate' ), 'wordgate-firewall' );
	}
}

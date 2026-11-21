<?php
/**
 * WP-CLI commands.
 *
 * @package WordGate
 */

namespace WordGate\Cli;

use WordGate\Firewall\WafConfig;
use WordGate\Firewall\WafInstaller;
use WordGate\Log\EventLog;
use WordGate\Login\TwoFactor;
use WordGate\Plugin;
use WordGate\Scanner\Issues;
use WordGate\Scanner\ScanRunner;
use WordGate\Settings;
use WordGate\Waf\IpUtil;
use WP_CLI;

/**
 * Manage WordGate security from the command line.
 */
final class Command {

	/**
	 * Run a full security scan.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format for issues.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp wordgate scan
	 */
	public function scan( $args, $assoc ) {
		$last = '';
		$s    = ScanRunner::runToCompletion(
			static function ( $s ) use ( &$last ) {
				$p = ScanRunner::publicState( $s );
				if ( $p['phase'] !== $last ) {
					WP_CLI::log( $p['phase'] . '…' );
					$last = $p['phase'];
				}
			}
		);
		if ( 'done' !== $s['status'] ) {
			WP_CLI::error( 'Scan failed: ' . implode( ' ', $s['notes'] ) );
		}
		foreach ( $s['notes'] as $note ) {
			WP_CLI::warning( $note );
		}
		$this->issues( array(), $assoc );
		WP_CLI::success( sprintf( 'Scanned %d files. %d issues (%d new).', $s['stats']['files_scanned'], $s['stats']['issues'], $s['stats']['new_issues'] ) );
	}

	/**
	 * List scan issues.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : open, ignored or resolved.
	 * ---
	 * default: open
	 * ---
	 *
	 * [--format=<format>]
	 * : table, json or csv.
	 * ---
	 * default: table
	 * ---
	 */
	public function issues( $args, $assoc ) {
		$status = isset( $assoc['status'] ) ? $assoc['status'] : 'open';
		$rows   = array_map(
			static function ( $i ) {
				return array(
					'id'       => $i['id'],
					'severity' => $i['severity'],
					'type'     => $i['type'],
					'title'    => $i['title'],
				);
			},
			Issues::all( $status )
		);
		if ( ! $rows ) {
			WP_CLI::log( 'No ' . $status . ' issues.' );
			return;
		}
		WP_CLI\Utils\format_items( isset( $assoc['format'] ) ? $assoc['format'] : 'table', $rows, array( 'id', 'severity', 'type', 'title' ) );
	}

	/**
	 * Block an IP address or CIDR range.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : IP or CIDR.
	 *
	 * [--minutes=<minutes>]
	 * : Duration; 0 = permanent.
	 * ---
	 * default: 0
	 * ---
	 *
	 * [--reason=<reason>]
	 * : Why.
	 *
	 * [--login-only]
	 * : Only block wp-login.php and xmlrpc.php.
	 */
	public function block( $args, $assoc ) {
		if ( ! IpUtil::isValidRange( $args[0] ) ) {
			WP_CLI::error( 'Invalid IP or CIDR.' );
		}
		$ok = Plugin::storage()->addBlock( $args[0], isset( $assoc['reason'] ) ? $assoc['reason'] : 'Blocked via WP-CLI', (int) $assoc['minutes'], isset( $assoc['login-only'] ) ? 'login' : 'all', 'cli' );
		$ok ? WP_CLI::success( "Blocked {$args[0]}." ) : WP_CLI::error( 'Could not write the block list. Is the data directory writable?' );
	}

	/**
	 * Remove a block.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : IP or CIDR exactly as listed.
	 */
	public function unblock( $args ) {
		Plugin::storage()->removeBlock( $args[0] );
		WP_CLI::success( "Unblocked {$args[0]}." );
	}

	/**
	 * List active blocks.
	 *
	 * [--format=<format>]
	 * : table, json or csv.
	 * ---
	 * default: table
	 * ---
	 */
	public function blocks( $args, $assoc ) {
		$rows = array();
		foreach ( Plugin::storage()->getBlocks() as $ip => $b ) {
			$rows[] = array(
				'ip'      => $ip,
				'scope'   => $b['scope'],
				'source'  => $b['source'],
				'reason'  => $b['reason'],
				'expires' => $b['expires'] ? gmdate( 'Y-m-d H:i', $b['expires'] ) . ' UTC' : 'never',
			);
		}
		WP_CLI\Utils\format_items( $assoc['format'], $rows, array( 'ip', 'scope', 'source', 'reason', 'expires' ) );
	}

	/**
	 * Show or change firewall status.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status | enable | learning | disable | install | install-extended | uninstall-extended | sync
	 *
	 * [--server=<server>]
	 * : For install-extended: apache-mod_php, litespeed, user-ini or manual. Auto-detected otherwise.
	 *
	 * ## EXAMPLES
	 *
	 *     wp wordgate waf status
	 *     wp wordgate waf learning
	 */
	public function waf( $args, $assoc ) {
		switch ( $args[0] ) {
			case 'status':
				$s = WafInstaller::status();
				WP_CLI::log( 'Mode:          ' . Settings::get( 'waf_mode' ) );
				WP_CLI::log( 'Protection:    ' . $s['mode'] );
				WP_CLI::log( 'Data dir:      ' . WORDGATE_DATA_DIR );
				WP_CLI::log( 'Rules loaded:  ' . count( WafConfig::rules() ) );
				WP_CLI::log( 'Active blocks: ' . count( Plugin::storage()->getBlocks() ) );
				return;
			case 'enable':
			case 'learning':
			case 'disable':
				Settings::update( array( 'waf_mode' => 'enable' === $args[0] ? 'enabled' : ( 'disable' === $args[0] ? 'disabled' : 'learning' ) ) );
				WP_CLI::success( 'Firewall mode: ' . Settings::get( 'waf_mode' ) );
				return;
			case 'install':
				$r = WafInstaller::installBasic();
				break;
			case 'install-extended':
				WafInstaller::installBasic();
				$r = WafInstaller::installExtended( isset( $assoc['server'] ) ? $assoc['server'] : WafInstaller::detectServer() );
				break;
			case 'uninstall-extended':
				WafInstaller::uninstallExtended();
				$r = true;
				break;
			case 'sync':
				$r = WafConfig::sync() ? true : new \WP_Error( 'sync', 'Could not write config.' );
				break;
			default:
				WP_CLI::error( 'Unknown action.' );
				return;
		}
		is_wp_error( $r ) ? WP_CLI::error( $r->get_error_message() ) : WP_CLI::success( 'Done.' );
	}

	/**
	 * Manage two-factor authentication.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status | reset
	 *
	 * [<user>]
	 * : User ID, login or email (for reset).
	 *
	 * ## EXAMPLES
	 *
	 *     wp wordgate 2fa reset admin
	 *
	 * @subcommand 2fa
	 */
	public function two_factor( $args ) {
		if ( 'status' === $args[0] ) {
			$rows = array();
			foreach ( get_users( array( 'role__in' => array( 'administrator', 'editor' ) ) ) as $u ) {
				$rows[] = array(
					'user' => $u->user_login,
					'role' => implode( ',', $u->roles ),
					'2fa'  => TwoFactor::isEnabled( $u->ID ) ? 'yes' : 'no',
				);
			}
			WP_CLI\Utils\format_items( 'table', $rows, array( 'user', 'role', '2fa' ) );
			return;
		}
		if ( 'reset' === $args[0] && isset( $args[1] ) ) {
			$user = is_numeric( $args[1] ) ? get_user_by( 'id', $args[1] ) : ( get_user_by( 'login', $args[1] ) ?: get_user_by( 'email', $args[1] ) );
			if ( ! $user ) {
				WP_CLI::error( 'User not found.' );
			}
			TwoFactor::disable( $user->ID );
			EventLog::add( '2fa_disabled', '', array( 'user_login' => $user->user_login, 'reason' => 'WP-CLI reset' ), 'medium' );
			WP_CLI::success( "Two-factor authentication removed for {$user->user_login}." );
			return;
		}
		WP_CLI::error( 'Usage: wp wordgate 2fa <status|reset> [<user>]' );
	}

	/**
	 * Import pending firewall events into the activity log.
	 */
	public function ingest() {
		WP_CLI::success( sprintf( 'Imported %d events.', EventLog::ingest() ) );
	}
}

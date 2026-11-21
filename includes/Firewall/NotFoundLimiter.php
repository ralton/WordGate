<?php
/**
 * Blocks IPs that generate an abnormal number of 404s — the fingerprint of
 * vulnerability scanners probing for plugin paths.
 *
 * @package WordGate
 */

namespace WordGate\Firewall;

use WordGate\Log\EventLog;
use WordGate\Plugin;
use WordGate\Settings;

final class NotFoundLimiter {

	public static function register() {
		if ( (int) Settings::get( 'not_found_limit' ) > 0 ) {
			add_action( 'template_redirect', array( __CLASS__, 'check' ), 999 );
		}
	}

	public static function check() {
		if ( ! is_404() || is_user_logged_in() ) {
			return;
		}
		$ip = Plugin::clientIp();
		if ( \WordGate\Waf\IpUtil::matchesAny( $ip, Settings::lines( 'allowlist_ips' ) ) ) {
			return;
		}
		$limit = (int) Settings::get( 'not_found_limit' );
		$count = Plugin::storage()->increment( '404:' . $ip, 60 );
		if ( $count > $limit ) {
			$minutes = max( 1, (int) Settings::get( 'rate_limit_block_minutes' ) );
			Plugin::storage()->addBlock( $ip, 'Too many 404s (scanner)', $minutes, 'all', '404_limit' );
			EventLog::add( 'block_404', $ip, array( 'reason' => sprintf( 'Exceeded %d not-found responses per minute', $limit ) ), 'medium' );
			wp_die( esc_html__( 'Too many requests.', 'wordgate' ), 429 );
		}
	}
}

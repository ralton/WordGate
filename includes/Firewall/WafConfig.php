<?php
/**
 * Translates WordPress settings into the WAF's standalone config file.
 *
 * @package WordGate
 */

namespace WordGate\Firewall;

use WordGate\Plugin;
use WordGate\Settings;

final class WafConfig {

	public static function sync() {
		$s = Settings::all();
		return Plugin::storage()->writeConfig(
			array(
				'mode'            => $s['waf_mode'],
				'ip_source'       => $s['ip_source'],
				'trusted_proxies' => Settings::lines( 'trusted_proxies' ),
				'allowlist_ips'   => Settings::lines( 'allowlist_ips' ),
				'disabled_rules'  => array_map( 'intval', (array) $s['disabled_rules'] ),
				'allow_rules'     => array_values( (array) $s['allow_rules'] ),
				'rate_limit'      => array(
					'enabled'             => (bool) $s['rate_limit_enabled'],
					'requests_per_minute' => (int) $s['rate_limit_rpm'],
					'action'              => $s['rate_limit_action'],
					'block_minutes'       => (int) $s['rate_limit_block_minutes'],
				),
				'block_page'      => array(
					'show_reason' => (bool) $s['block_page_show_reason'],
				),
				'auth_secret'     => self::secret(),
			)
		);
	}

	/**
	 * Server-side secret used to sign the administrator bypass cookie.
	 */
	public static function secret() {
		$secret = get_option( 'wordgate_auth_secret' );
		if ( ! $secret ) {
			$secret = bin2hex( random_bytes( 32 ) );
			update_option( 'wordgate_auth_secret', $secret, false );
		}
		return $secret;
	}

	/**
	 * Rotate the signing secret and push it to the WAF config, immediately
	 * invalidating all existing wordgate_admin bypass cookies.
	 */
	public static function rotateSecret() {
		$secret = bin2hex( random_bytes( 32 ) );
		update_option( 'wordgate_auth_secret', $secret, false );
		self::sync();
		return $secret;
	}

	/**
	 * All rules currently loaded (for the admin UI).
	 *
	 * @return \WordGate\Waf\Rule[]
	 */
	public static function rules() {
		return Plugin::storage()->loadRules( WORDGATE_DIR . '/waf/rules/default.json' );
	}
}

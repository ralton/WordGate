<?php
/**
 * The firewall decision engine.
 *
 * Evaluation order:
 *   1. Allowlisted IP          -> allow (nothing else runs)
 *   2. Active IP block         -> 403
 *   3. Rate limit              -> 429 (throttle) or block the IP
 *   4. Rules                   -> 403 on first blocking match (or log in learning mode)
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Engine {

	const ALLOW = 'allow';
	const BLOCK = 'block';
	const THROTTLE = 'throttle';

	/** @var Storage */
	private $storage;
	/** @var array */
	private $config;
	/** @var Rule[] */
	private $rules;

	/**
	 * @param Rule[] $rules
	 */
	public function __construct( Storage $storage, array $config, array $rules ) {
		$this->storage = $storage;
		$this->config  = array_replace_recursive( Storage::defaultConfig(), $config );
		$this->rules   = $rules;
	}

	/**
	 * Inspect a request and return a decision. Does not send output.
	 *
	 * @return array{action:string,status:int,reason:string,rule:?Rule,match:?array,logged:array[]}
	 */
	public function inspect( Request $request ) {
		$decision = array(
			'action' => self::ALLOW,
			'status' => 200,
			'reason' => '',
			'rule'   => null,
			'match'  => null,
			'logged' => array(),
		);

		if ( 'disabled' === $this->config['mode'] ) {
			return $decision;
		}

		$this->currentPath = $request->decodedPath();
		$ip = $request->ip();

		// 1. Allowlist.
		if ( IpUtil::matchesAny( $ip, (array) $this->config['allowlist_ips'] ) ) {
			return $decision;
		}

		// 2. IP blocks are enforced even in learning mode — they are explicit admin intent.
		$block = $this->storage->findBlock( $ip, $request->isLoginRequest() );
		if ( $block ) {
			$decision['action'] = self::BLOCK;
			$decision['status'] = 403;
			$decision['reason'] = 'Blocked IP' . ( '' !== $block['reason'] ? ': ' . $block['reason'] : '' );
			$this->log( $request, 'ip_block', $decision['reason'], null, null, $decision );
			return $decision;
		}

		// 3. Rate limiting.
		$rl = $this->config['rate_limit'];
		if ( ! empty( $rl['enabled'] ) && (int) $rl['requests_per_minute'] > 0 ) {
			$count = $this->storage->increment( 'req:' . $ip, 60 );
			if ( $count > (int) $rl['requests_per_minute'] ) {
				if ( 'block' === $rl['action'] ) {
					$this->storage->addBlock( $ip, 'Exceeded rate limit', max( 1, (int) $rl['block_minutes'] ), 'all', 'rate_limit' );
					$decision['action'] = self::BLOCK;
					$decision['status'] = 403;
				} else {
					$decision['action'] = self::THROTTLE;
					$decision['status'] = 429;
				}
				$decision['reason'] = 'Rate limit exceeded';
				// Only log the first overflow per window to avoid flooding the log.
				if ( $count === (int) $rl['requests_per_minute'] + 1 ) {
					$this->log( $request, 'rate_limit', $decision['reason'], null, null, $decision );
				}
				return $decision;
			}
		}

		// 4. Rules.
		$isAdmin  = $this->isVerifiedAdmin( $request );
		$learning = 'learning' === $this->config['mode'];
		$disabled = array_map( 'intval', (array) $this->config['disabled_rules'] );
		$allowFn  = array( $this, 'isAllowedParam' );

		foreach ( $this->rules as $rule ) {
			if ( in_array( $rule->id, $disabled, true ) ) {
				continue;
			}
			if ( $isAdmin && $rule->adminBypass ) {
				continue;
			}
			$match = $rule->evaluate( $request, $allowFn );
			if ( null === $match ) {
				continue;
			}

			if ( 'log' === $rule->action || $learning ) {
				$this->log( $request, $learning ? 'learning' : 'rule_log', $rule->name, $rule, $match, $decision );
				$decision['logged'][] = $match;
				continue;
			}

			$decision['action'] = self::BLOCK;
			$decision['status'] = 403;
			$decision['reason'] = $rule->name;
			$decision['rule']   = $rule;
			$decision['match']  = $match;
			$this->log( $request, 'rule_block', $rule->name, $rule, $match, $decision );
			return $decision;
		}

		return $decision;
	}

	/**
	 * Allowlist callback used by Rule::evaluate(). Lets site owners suppress a
	 * false positive for a specific rule / path / parameter combination.
	 */
	public function isAllowedParam( Rule $rule, $target, $param ) {
		foreach ( (array) $this->config['allow_rules'] as $a ) {
			$ruleId = isset( $a['rule_id'] ) ? (int) $a['rule_id'] : 0;
			if ( 0 !== $ruleId && $ruleId !== $rule->id ) {
				continue;
			}
			if ( ! empty( $a['param'] ) && $a['param'] !== $param && $a['param'] !== $target . '.' . $param ) {
				continue;
			}
			if ( ! empty( $a['path'] ) ) {
				if ( null === $this->currentPath || ! @preg_match( Rule::compile( $a['path'] ), $this->currentPath ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
			}
			return true;
		}
		return false;
	}

	/** @var string|null Path of the request under inspection, for allow_rules. */
	private $currentPath;

	/**
	 * Inspect and, if blocked, send the response and terminate.
	 */
	public function run( Request $request ) {
		$decision = $this->inspect( $request );
		if ( self::ALLOW !== $decision['action'] ) {
			Response::send( $decision, $request, $this->config );
		}
		return $decision;
	}

	/**
	 * Administrators logged in to WordPress receive a signed cookie (set by the
	 * plugin) that lets the WAF skip rules flagged admin_bypass — e.g. HTML or
	 * script in post content. It is an HMAC over user id + expiry using a secret
	 * that only exists server side, so it cannot be forged.
	 */
	public function isVerifiedAdmin( Request $request ) {
		$secret = (string) $this->config['auth_secret'];
		$cookie = $request->cookie( 'wordgate_admin' );
		if ( '' === $secret || '' === $cookie ) {
			return false;
		}
		return self::verifyAdminToken( $cookie, $secret );
	}

	public static function makeAdminToken( $userId, $expires, $secret ) {
		$payload = (int) $userId . '|' . (int) $expires;
		return $payload . '|' . hash_hmac( 'sha256', $payload, $secret );
	}

	public static function verifyAdminToken( $token, $secret ) {
		$parts = explode( '|', (string) $token );
		if ( 3 !== count( $parts ) || (int) $parts[1] < time() ) {
			return false;
		}
		$expected = hash_hmac( 'sha256', $parts[0] . '|' . $parts[1], $secret );
		return hash_equals( $expected, $parts[2] );
	}

	private function log( Request $request, $type, $reason, $rule, $match, array $decision ) {
		$this->storage->appendLog(
			array(
				'time'     => time(),
				'type'     => $type,
				'ip'       => $request->ip(),
				'method'   => $request->method(),
				'uri'      => substr( $request->uri(), 0, 1024 ),
				'ua'       => substr( $request->header( 'user-agent' ), 0, 512 ),
				'reason'   => $reason,
				'rule_id'  => $rule ? $rule->id : 0,
				'category' => $rule ? $rule->category : '',
				'severity' => $rule ? $rule->severity : '',
				'match'    => $match,
				'status'   => self::ALLOW === $decision['action'] ? 200 : $decision['status'],
			)
		);
	}
}

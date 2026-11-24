<?php
/**
 * A single declarative WAF rule.
 *
 * Rule schema (JSON):
 * {
 *   "id": 1001,                       // unique integer
 *   "name": "SQLi: UNION SELECT",
 *   "category": "sqli",               // sqli|xss|lfi|rce|upload|scanner|wordpress|...
 *   "severity": "high",               // low|medium|high|critical
 *   "action": "block",                // block|log
 *   "targets": ["query","body"],      // see Request::target()
 *   "transforms": ["urldecode","lowercase"],
 *   "pattern": "...",                 // PCRE without delimiters, compiled with /iSs flags (i = case-insensitive)
 *   "paths": ["regex", ...],          // optional: rule only applies when path matches one
 *   "methods": ["POST"],              // optional
 *   "exclude_params": ["regex"],      // optional: parameter names to skip
 *   "admin_bypass": true              // optional: skipped for verified administrators
 * }
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Rule {

	public $id;
	public $name;
	public $category;
	public $severity;
	public $action;
	public $targets;
	public $transforms;
	public $pattern;
	public $paths;
	public $methods;
	public $excludeParams;
	public $adminBypass;

	/** @var string Compiled regex. */
	private $regex;

	public function __construct( array $def ) {
		$this->id            = (int) $def['id'];
		$this->name          = (string) $def['name'];
		$this->category      = isset( $def['category'] ) ? (string) $def['category'] : 'generic';
		$this->severity      = isset( $def['severity'] ) ? (string) $def['severity'] : 'medium';
		$this->action        = isset( $def['action'] ) && 'log' === $def['action'] ? 'log' : 'block';
		$this->targets       = isset( $def['targets'] ) ? (array) $def['targets'] : array( 'query', 'body', 'cookies' );
		$this->transforms    = isset( $def['transforms'] ) ? (array) $def['transforms'] : array();
		$this->pattern       = (string) $def['pattern'];
		$this->paths         = isset( $def['paths'] ) ? (array) $def['paths'] : array();
		$this->methods       = isset( $def['methods'] ) ? array_map( 'strtoupper', (array) $def['methods'] ) : array();
		$this->excludeParams = isset( $def['exclude_params'] ) ? (array) $def['exclude_params'] : array();
		$this->adminBypass   = ! empty( $def['admin_bypass'] );
		$this->regex         = self::compile( $this->pattern );
	}

	/**
	 * Wrap a raw pattern in delimiters. Unescaped '#' characters are escaped so
	 * patterns never need to, without double-escaping existing '\#' sequences.
	 */
	public static function compile( $pattern ) {
		$escaped = (string) preg_replace( '/(?<!\\\\)((?:\\\\\\\\)*)#/', '$1\\#', (string) $pattern );
		return '#' . $escaped . '#iSs';
	}

	/**
	 * Is the pattern a valid PCRE? Used by tests and the rule loader.
	 */
	public function isValid() {
		return false !== @preg_match( $this->regex, '' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Does this rule apply to the request's method and path?
	 */
	public function appliesTo( Request $request ) {
		if ( $this->methods && ! in_array( $request->method(), $this->methods, true ) ) {
			return false;
		}
		if ( $this->paths ) {
			$path = $request->decodedPath();
			foreach ( $this->paths as $p ) {
				if ( preg_match( self::compile( $p ), $path ) ) {
					return true;
				}
			}
			return false;
		}
		return true;
	}

	/**
	 * Evaluate the rule.
	 *
	 * @param callable $isAllowed fn(Rule $rule, string $target, string $param): bool — allowlist hook.
	 * @return array|null Match details or null.
	 */
	public function evaluate( Request $request, ?callable $isAllowed = null ) {
		if ( ! $this->appliesTo( $request ) ) {
			return null;
		}
		foreach ( $this->targets as $target ) {
			foreach ( $request->target( $target ) as $param => $value ) {
				if ( '' === $value || $this->isExcluded( (string) $param ) ) {
					continue;
				}
				if ( $isAllowed && $isAllowed( $this, $target, (string) $param ) ) {
					continue;
				}
				$subject = Transforms::apply( $value, $this->transforms );
				if ( preg_match( $this->regex, $subject, $m ) ) {
					return array(
						'rule_id' => $this->id,
						'target'  => $target,
						'param'   => (string) $param,
						'matched' => substr( $m[0], 0, 200 ),
					);
				}
			}
		}
		return null;
	}

	private function isExcluded( $param ) {
		foreach ( $this->excludeParams as $p ) {
			if ( preg_match( self::compile( '^(?:' . $p . ')$' ), $param ) ) {
				return true;
			}
		}
		return false;
	}
}

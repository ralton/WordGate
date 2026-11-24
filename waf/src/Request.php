<?php
/**
 * Immutable snapshot of the incoming HTTP request, flattened into
 * inspectable "targets" for the rule engine.
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class Request {

	/** Values longer than this are truncated before inspection (performance). */
	const MAX_VALUE_LENGTH = 65536;

	/** Maximum JSON body size decoded into structured parameters before falling back. */
	const MAX_JSON_BODY = 2097152;

	/** Bytes read from the start (and end, for large uploads) of each uploaded file. */
	const MAX_FILE_SNIFF = 65536;

	/** @var string */
	private $ip;
	/** @var string */
	private $method;
	/** @var string */
	private $uri;
	/** @var string */
	private $path;
	/** @var array */
	private $query;
	/** @var array */
	private $body;
	/** @var array */
	private $cookies;
	/** @var array */
	private $headers;
	/** @var array */
	private $files;
	/** @var string */
	private $rawBody;

	/** @var array<string,array<string,string>> Memoised flattened targets. */
	private $targetCache = array();

	public function __construct( $ip, $method, $uri, array $query = array(), array $body = array(), array $cookies = array(), array $headers = array(), array $files = array(), $rawBody = '' ) {
		$this->ip      = (string) $ip;
		$this->method  = strtoupper( (string) $method );
		$this->uri     = (string) $uri;
		$path          = parse_url( $this->uri, PHP_URL_PATH ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$this->path    = is_string( $path ) ? $path : '/';
		$this->query   = $query;
		$this->body    = $body;
		$this->cookies = $cookies;
		$this->headers = array_change_key_case( $headers, CASE_LOWER );
		$this->files   = $files;
		$this->rawBody = (string) $rawBody;
	}

	/**
	 * Build from PHP superglobals.
	 *
	 * @param string   $ipSource       See IpUtil::clientIp().
	 * @param string[] $trustedProxies See IpUtil::clientIp().
	 */
	public static function fromGlobals( $ipSource = 'REMOTE_ADDR', array $trustedProxies = array() ) {
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$headers = array();
		foreach ( $_SERVER as $key => $value ) {
			if ( 0 === strpos( $key, 'HTTP_' ) ) {
				$headers[ str_replace( '_', '-', strtolower( substr( $key, 5 ) ) ) ] = (string) $value;
			}
		}
		if ( isset( $_SERVER['CONTENT_TYPE'] ) ) {
			$headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
		}

		$rawBody = '';
		$body    = $_POST;
		$method  = strtoupper( isset( $_SERVER['REQUEST_METHOD'] ) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET' );
		if ( 'GET' !== $method && 'HEAD' !== $method ) {
			// php://input is re-readable since PHP 5.6, so WordPress still gets it.
			$ctype  = isset( $headers['content-type'] ) ? strtolower( $headers['content-type'] ) : '';
			$isJson = empty( $body ) && false !== strpos( $ctype, 'json' );
			$limit  = $isJson ? self::MAX_JSON_BODY : self::MAX_VALUE_LENGTH;
			$input  = (string) file_get_contents( 'php://input', false, null, 0, $limit ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( $isJson && '' !== $input ) {
				$decoded = json_decode( $input, true );
				if ( is_array( $decoded ) ) {
					$body = $decoded;
				}
			}
			$rawBody = strlen( $input ) > self::MAX_VALUE_LENGTH ? substr( $input, 0, self::MAX_VALUE_LENGTH ) : $input;
		}

		$files = array();
		foreach ( $_FILES as $field => $file ) {
			self::collectFiles( $field, $file, $files );
		}

		return new self(
			IpUtil::clientIp( $_SERVER, $ipSource, $trustedProxies ),
			$method,
			isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/',
			$_GET,
			is_array( $body ) ? $body : array(),
			$_COOKIE,
			$headers,
			$files,
			$rawBody
		);
		// phpcs:enable
	}

	/**
	 * Normalise PHP's awkward multi-file $_FILES layout to a flat list.
	 */
	private static function collectFiles( $field, $file, array &$out ) {
		if ( ! is_array( $file ) || ! isset( $file['name'] ) ) {
			return;
		}
		if ( is_array( $file['name'] ) ) {
			foreach ( array_keys( $file['name'] ) as $k ) {
				self::collectFiles(
					$field . '[' . $k . ']',
					array(
						'name'     => $file['name'][ $k ],
						'tmp_name' => isset( $file['tmp_name'][ $k ] ) ? $file['tmp_name'][ $k ] : '',
					),
					$out
				);
			}
			return;
		}
		$out[ $field ] = array(
			'name'     => (string) $file['name'],
			'tmp_name' => isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '',
		);
	}

	public function ip() {
		return $this->ip;
	}

	public function method() {
		return $this->method;
	}

	public function uri() {
		return $this->uri;
	}

	public function path() {
		return $this->path;
	}

	/**
	 * URL-decoded, null-stripped, slash-collapsed path used for path scoping
	 * and login-endpoint detection so encodings and PATH_INFO cannot evade rules.
	 */
	public function decodedPath() {
		$path = rawurldecode( $this->path );
		$path = str_replace( "\0", '', $path );
		return (string) preg_replace( '#/{2,}#', '/', $path );
	}

	public function header( $name ) {
		$name = strtolower( $name );
		return isset( $this->headers[ $name ] ) ? $this->headers[ $name ] : '';
	}

	public function cookie( $name ) {
		return isset( $this->cookies[ $name ] ) && is_string( $this->cookies[ $name ] ) ? $this->cookies[ $name ] : '';
	}

	/**
	 * Is this a request to a login endpoint (including PATH_INFO / encoded forms)?
	 */
	public function isLoginRequest() {
		return (bool) preg_match( '#(?:^|/)(?:wp-login|xmlrpc)\.php(?:/|$)#i', $this->decodedPath() );
	}

	/**
	 * Return a flat map of "parameter name" => "value" for a target.
	 *
	 * Supported targets: query, body, cookies, headers, uri, path, user_agent,
	 * query_keys, body_keys, files (upload file names), file_contents, raw_body.
	 *
	 * @return array<string,string>
	 */
	public function target( $target ) {
		if ( isset( $this->targetCache[ $target ] ) ) {
			return $this->targetCache[ $target ];
		}
		$out = array();
		switch ( $target ) {
			case 'query':
				self::flatten( $this->query, '', $out );
				break;
			case 'body':
				self::flatten( $this->body, '', $out );
				break;
			case 'cookies':
				self::flatten( $this->cookies, '', $out );
				break;
			case 'headers':
				foreach ( $this->headers as $k => $v ) {
					if ( 'cookie' !== $k ) { // Cookies are inspected separately.
						$out[ $k ] = self::cap( $v );
					}
				}
				break;
			case 'query_keys':
				$tmp = array();
				self::flatten( $this->query, '', $tmp );
				foreach ( array_keys( $tmp ) as $k ) {
					$out[ $k ] = (string) $k;
				}
				break;
			case 'body_keys':
				$tmp = array();
				self::flatten( $this->body, '', $tmp );
				foreach ( array_keys( $tmp ) as $k ) {
					$out[ $k ] = (string) $k;
				}
				break;
			case 'uri':
				$out['uri'] = self::cap( rawurldecode( $this->uri ) );
				break;
			case 'path':
				$out['path'] = self::cap( rawurldecode( $this->path ) );
				break;
			case 'user_agent':
				$out['user-agent'] = self::cap( $this->header( 'user-agent' ) );
				break;
			case 'files':
				foreach ( $this->files as $field => $f ) {
					$out[ $field ] = self::cap( $f['name'] );
				}
				break;
			case 'file_contents':
				foreach ( $this->files as $field => $f ) {
					if ( '' !== $f['tmp_name'] && is_uploaded_file( $f['tmp_name'] ) ) {
						$size = @filesize( $f['tmp_name'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$head = (string) file_get_contents( $f['tmp_name'], false, null, 0, self::MAX_FILE_SNIFF ); // phpcs:ignore WordPress.WP.AlternativeFunctions
						if ( false !== $size && $size > self::MAX_FILE_SNIFF ) {
							$tail          = (string) file_get_contents( $f['tmp_name'], false, null, max( self::MAX_FILE_SNIFF, $size - self::MAX_FILE_SNIFF ), self::MAX_FILE_SNIFF ); // phpcs:ignore WordPress.WP.AlternativeFunctions
							$out[ $field ] = $head . "\n" . $tail;
						} else {
							$out[ $field ] = $head;
						}
					} elseif ( isset( $f['content'] ) ) { // Test harness.
						$content = (string) $f['content'];
						if ( strlen( $content ) > self::MAX_FILE_SNIFF ) {
							$out[ $field ] = substr( $content, 0, self::MAX_FILE_SNIFF ) . "\n" . substr( $content, -self::MAX_FILE_SNIFF );
						} else {
							$out[ $field ] = $content;
						}
					}
				}
				break;
			case 'raw_body':
				if ( '' !== $this->rawBody ) {
					$out['raw_body'] = self::cap( $this->rawBody );
				}
				break;
		}
		$this->targetCache[ $target ] = $out;
		return $out;
	}

	/**
	 * Flatten nested arrays: a[b][c] => value.
	 */
	private static function flatten( $data, $prefix, array &$out, $depth = 0 ) {
		if ( $depth > 16 ) {
			return;
		}
		foreach ( (array) $data as $k => $v ) {
			$key = '' === $prefix ? (string) $k : $prefix . '[' . $k . ']';
			if ( is_array( $v ) ) {
				self::flatten( $v, $key, $out, $depth + 1 );
			} elseif ( is_scalar( $v ) ) {
				$out[ $key ] = self::cap( (string) $v );
			}
		}
	}

	private static function cap( $value ) {
		$value = (string) $value;
		return strlen( $value ) > self::MAX_VALUE_LENGTH ? substr( $value, 0, self::MAX_VALUE_LENGTH ) : $value;
	}
}

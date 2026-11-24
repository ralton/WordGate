<?php
/**
 * Pure-PHP libinjection-style SQL-injection tokenizer and fingerprint matcher.
 *
 * No WordPress dependency; lives under waf/src/ so it runs before WordPress.
 *
 * Pipeline:
 *   1. Fast pre-filter skips inputs that cannot form a SQLi token sequence.
 *   2. Tokenise the input in up to three SQL contexts: as-is, inside ', inside ".
 *   3. Fold adjacent tokens (arithmetic, functions, comma lists, comments, clauses)
 *      into a compact 1–5 character fingerprint (e.g. "s&1c", "1UE1k", "s&s=s").
 *   4. O(1) lookup against waf/src/SqliFingerprints.php (generated from the
 *      training corpus in tools/build-sqli-fingerprints.py).
 *
 * @package WordGate
 */

namespace WordGate\Waf;

final class SqliTokenizer {

	const MAX_INPUT_BYTES = 4096;
	const MAX_TOKENS      = 24;

	/** @var array<string,true>|null */
	private static $fingerprints;

	/** High-confidence SQL attack/database functions (token 'F'). */
	const ATTACK_FUNCTIONS = array(
		'sleep' => true, 'benchmark' => true, 'pg_sleep' => true, 'extractvalue' => true,
		'updatexml' => true, 'load_file' => true, 'gtid_subset' => true, 'dbms_pipe' => true,
		'utl_inaddr' => true, 'utl_http' => true, 'utl_tcp' => true, 'ctxsys' => true,
		'xp_cmdshell' => true, 'sp_executesql' => true, 'pg_read_file' => true, 'pg_ls_dir' => true,
		'lo_import' => true, 'name_const' => true, 'get_lock' => true, 'is_free_lock' => true,
		'is_used_lock' => true, 'group_concat' => true, 'concat_ws' => true, 'inet_aton' => true,
		'inet_server_addr' => true, 'make_set' => true, 'export_set' => true, 'json_keys' => true,
		'geometrycollection' => true, 'multipoint' => true, 'linestring' => true, 'randomblob' => true,
		'zeroblob' => true, 'sqlite_version' => true, 'openrowset' => true, 'opendatasource' => true,
		'suser_sname' => true, 'is_srvrolemember' => true, 'sys_context' => true, 'xmltype' => true,
		'generate_series' => true,
	);

	/** General SQL functions (token 'f'; only flagged inside SQL syntax context). */
	const GENERAL_FUNCTIONS = array(
		'concat' => true, 'char' => true, 'chr' => true, 'ascii' => true, 'ord' => true,
		'substring' => true, 'substr' => true, 'mid' => true, 'left' => true, 'right' => true,
		'length' => true, 'char_length' => true, 'character_length' => true, 'version' => true,
		'database' => true, 'schema' => true, 'user' => true, 'current_user' => true,
		'system_user' => true, 'session_user' => true, 'current_database' => true, 'floor' => true,
		'rand' => true, 'exp' => true, 'cast' => true, 'convert' => true, 'coalesce' => true,
		'if' => true, 'ifnull' => true, 'nullif' => true, 'hex' => true, 'unhex' => true,
		'md5' => true, 'sha1' => true, 'sha2' => true, 'count' => true, 'elt' => true,
		'field' => true, 'polygon' => true, 'reverse' => true, 'repeat' => true, 'replace' => true,
		'locate' => true, 'instr' => true, 'position' => true, 'conv' => true, 'oct' => true,
		'bin' => true, 'uuid' => true, 'row_count' => true, 'found_rows' => true,
		'last_insert_id' => true, 'db_name' => true, 'host_name' => true, 'to_char' => true,
		'to_number' => true, 'rawtohex' => true, 'charindex' => true, 'patindex' => true,
		'stuff' => true, 'quotename' => true, 'unicode' => true, 'typeof' => true,
		'release_lock' => true,
	);

	const STMT_VERBS = array(
		'select' => true, 'drop' => true, 'delete' => true, 'insert' => true, 'update' => true,
		'alter' => true, 'create' => true, 'truncate' => true, 'exec' => true, 'execute' => true,
		'declare' => true, 'waitfor' => true, 'shutdown' => true, 'grant' => true, 'revoke' => true,
		'load' => true, 'show' => true, 'call' => true, 'prepare' => true, 'deallocate' => true,
		'describe' => true, 'explain' => true, 'handler' => true, 'lock' => true, 'savepoint' => true,
		'rollback' => true, 'commit' => true,
	);

	const UNION_WORDS = array(
		'union' => true, 'intersect' => true, 'except' => true,
	);

	const LOGIC_WORDS = array(
		'and' => true, 'or' => true, 'xor' => true,
	);

	const COMP_WORDS = array(
		'like' => true, 'rlike' => true, 'regexp' => true, 'sounds' => true,
	);

	const CONST_WORDS = array(
		'null' => true, 'true' => true, 'false' => true,
	);

	const SCHEMA_WORDS = array(
		'information_schema' => true, 'pg_catalog' => true, 'mysql' => true, 'sys' => true,
		'syscolumns' => true, 'sysobjects' => true, 'sqlite_master' => true,
		'sqlite_temp_master' => true, 'all_tables' => true, 'user_tables' => true,
		'dba_users' => true, 'v$version' => true,
	);

	const CLAUSE_WORDS = array(
		'from' => true, 'where' => true, 'having' => true, 'order' => true, 'group' => true,
		'by' => true, 'into' => true, 'outfile' => true, 'dumpfile' => true, 'limit' => true,
		'offset' => true, 'join' => true, 'inner' => true, 'left' => true, 'right' => true,
		'outer' => true, 'cross' => true, 'values' => true, 'table' => true, 'database' => true,
		'schema' => true, 'case' => true, 'when' => true, 'then' => true, 'else' => true,
		'end' => true, 'as' => true, 'all' => true, 'distinct' => true, 'exists' => true,
		'between' => true, 'in' => true, 'is' => true, 'not' => true, 'delay' => true,
		'dual' => true, 'for' => true, 'top' => true, 'procedure' => true, 'analyse' => true,
		'binary' => true, 'div' => true, 'mod' => true, 'user' => true, 'index' => true,
		'view' => true, 'trigger' => true, 'function' => true, 'column' => true, 'to' => true,
		'default' => true, 'asc' => true, 'desc' => true, 'collate' => true, 'using' => true,
		'on' => true, 'any' => true, 'some' => true, 'fetch' => true, 'next' => true,
		'rows' => true, 'only' => true, 'set' => true, 'time' => true, 'wait' => true,
		'bulk' => true, 'open' => true, 'table_name' => true, 'column_name' => true,
		'schema_name' => true, 'tables' => true, 'columns' => true,
	);

	const PACKAGE_PREFIXES = array(
		'dbms_pipe' => true, 'utl_inaddr' => true, 'utl_http' => true, 'utl_tcp' => true, 'ctxsys' => true,
	);

	/**
	 * Load the known-SQLi fingerprint lookup map (cached in memory).
	 *
	 * @return array<string,true>
	 */
	public static function fingerprints() {
		if ( null === self::$fingerprints ) {
			$data               = include __DIR__ . '/SqliFingerprints.php';
			self::$fingerprints = is_array( $data ) ? $data : array();
		}
		return self::$fingerprints;
	}

	/**
	 * Inspect a string across all three SQL contexts (as-is, ', ").
	 *
	 * @return array{fingerprint:string,context:string}|null
	 */
	public static function detect( $input ) {
		$input = (string) $input;
		$len   = strlen( $input );
		if ( $len < 4 ) {
			return null;
		}

		// Ultra-fast pre-filter: skip values with no SQL metacharacters and no SQL keywords.
		if ( false === strpbrk( $input, "'\"`=()<>;#/*" ) && false === strpos( $input, '--' ) ) {
			if ( ! preg_match( '/\b(?:union|select|information_schema|pg_catalog|sqlite_master)\b/i', $input ) ) {
				return null;
			}
		}

		$known = self::fingerprints();

		// Context 1: as-is.
		$fp = self::fingerprint( $input, 'none' );
		if ( isset( $known[ $fp ] ) ) {
			return array( 'fingerprint' => $fp, 'context' => 'none' );
		}

		// Context 2: inside single-quoted string.
		if ( false !== strpos( $input, "'" ) ) {
			$fp = self::fingerprint( $input, "'" );
			if ( isset( $known[ $fp ] ) ) {
				return array( 'fingerprint' => $fp, 'context' => "'" );
			}
		}

		// Context 3: inside double-quoted string.
		if ( false !== strpos( $input, '"' ) ) {
			$fp = self::fingerprint( $input, '"' );
			if ( isset( $known[ $fp ] ) ) {
				return array( 'fingerprint' => $fp, 'context' => '"' );
			}
		}

		return null;
	}

	/**
	 * Tokenise and fold an input in a single context into a <=5-char fingerprint.
	 */
	public static function fingerprint( $input, $context = 'none' ) {
		return self::fold( self::tokenize( $input, $context ) );
	}

	/**
	 * Lex SQL input into [type, value] pairs.
	 *
	 * @return array<int,array{0:string,1:string}>
	 */
	public static function tokenize( $input, $context = 'none', $maxTokens = self::MAX_TOKENS ) {
		$s = (string) $input;
		if ( "'" === $context ) {
			$s = "'" . $s;
		} elseif ( '"' === $context ) {
			$s = '"' . $s;
		}
		if ( strlen( $s ) > self::MAX_INPUT_BYTES ) {
			$s = substr( $s, 0, self::MAX_INPUT_BYTES );
		}

		$n      = strlen( $s );
		$i      = 0;
		$tokens = array();
		$count  = 0;

		while ( $i < $n && $count < $maxTokens ) {
			$ch = $s[ $i ];

			// Whitespace.
			if ( ' ' === $ch || "\t" === $ch || "\r" === $ch || "\n" === $ch || "\x0b" === $ch || "\x0c" === $ch ) {
				++$i;
				continue;
			}

			// Single/double quoted string literal.
			if ( "'" === $ch || '"' === $ch ) {
				$q = $ch;
				++$i;
				while ( $i < $n ) {
					$c = $s[ $i ];
					if ( '\\' === $c && $i + 1 < $n ) {
						$i += 2;
						continue;
					}
					if ( $c === $q ) {
						if ( $i + 1 < $n && $s[ $i + 1 ] === $q ) {
							$i += 2;
							continue;
						}
						++$i;
						break;
					}
					++$i;
				}
				$tokens[] = array( 's', $q );
				++$count;
				continue;
			}

			// Backtick identifier.
			if ( '`' === $ch ) {
				++$i;
				$start = $i;
				while ( $i < $n && '`' !== $s[ $i ] ) {
					++$i;
				}
				$val = strtolower( substr( $s, $start, $i - $start ) );
				if ( $i < $n ) {
					++$i;
				}
				$tokens[] = array( isset( self::SCHEMA_WORDS[ $val ] ) ? 'I' : 'n', $val );
				++$count;
				continue;
			}

			// Block comment /* ... */ or MySQL conditional comment /*!50000 ... */.
			if ( '/' === $ch && $i + 1 < $n && '*' === $s[ $i + 1 ] ) {
				if ( $i + 2 < $n && '!' === $s[ $i + 2 ] ) {
					$i += 3;
					while ( $i < $n && $s[ $i ] >= '0' && $s[ $i ] <= '9' ) {
						++$i;
					}
					continue;
				}
				$end = strpos( $s, '*/', $i + 2 );
				$i   = false === $end ? $n : $end + 2;
				if ( $i >= $n ) {
					$tokens[] = array( 'c', '/*' );
					++$count;
				}
				continue;
			}

			// Closing */ from an unwrapped MySQL conditional comment.
			if ( '*' === $ch && $i + 1 < $n && '/' === $s[ $i + 1 ] ) {
				$i += 2;
				continue;
			}

			// Line comment --.
			if ( '-' === $ch && $i + 1 < $n && '-' === $s[ $i + 1 ] ) {
				if ( $i + 2 >= $n || false !== strpos( " \t\r\n+-#", $s[ $i + 2 ] ) ) {
					$nl       = strpos( $s, "\n", $i + 2 );
					$i        = false === $nl ? $n : $nl + 1;
					$tokens[] = array( 'c', '--' );
					++$count;
					continue;
				}
			}

			// Hash comment #.
			if ( '#' === $ch ) {
				$nl       = strpos( $s, "\n", $i + 1 );
				$i        = false === $nl ? $n : $nl + 1;
				$tokens[] = array( 'c', '#' );
				++$count;
				continue;
			}

			// SQL variable @var or @@var.
			if ( '@' === $ch ) {
				$j = $i + 1;
				if ( $j < $n && '@' === $s[ $j ] ) {
					++$j;
				}
				$start = $j;
				while ( $j < $n && ( ctype_alnum( $s[ $j ] ) || '_' === $s[ $j ] ) ) {
					++$j;
				}
				if ( $j > $start ) {
					$tokens[] = array( 'v', strtolower( substr( $s, $i, $j - $i ) ) );
					++$count;
					$i = $j;
					continue;
				}
				++$i;
				continue;
			}

			// Numeric & hex literals.
			if ( ( $ch >= '0' && $ch <= '9' ) || ( '.' === $ch && $i + 1 < $n && $s[ $i + 1 ] >= '0' && $s[ $i + 1 ] <= '9' ) ) {
				$j = $i;
				if ( '0' === $ch && $i + 1 < $n && ( 'x' === $s[ $i + 1 ] || 'X' === $s[ $i + 1 ] ) ) {
					$j += 2;
					while ( $j < $n && ctype_xdigit( $s[ $j ] ) ) {
						++$j;
					}
				} else {
					while ( $j < $n && ( ( $s[ $j ] >= '0' && $s[ $j ] <= '9' ) || '.' === $s[ $j ] ) ) {
						++$j;
					}
					if ( $j < $n && ( 'e' === $s[ $j ] || 'E' === $s[ $j ] ) && $j + 1 < $n && ( ( $s[ $j + 1 ] >= '0' && $s[ $j + 1 ] <= '9' ) || '+' === $s[ $j + 1 ] || '-' === $s[ $j + 1 ] ) ) {
						$j += 2;
						while ( $j < $n && $s[ $j ] >= '0' && $s[ $j ] <= '9' ) {
							++$j;
						}
					}
				}
				$tokens[] = array( '1', substr( $s, $i, $j - $i ) );
				++$count;
				$i = $j;
				continue;
			}

			// Barewords, keywords, functions.
			if ( ctype_alpha( $ch ) || '_' === $ch ) {
				$j = $i + 1;
				while ( $j < $n && ( ctype_alnum( $s[ $j ] ) || '_' === $s[ $j ] || '$' === $s[ $j ] ) ) {
					++$j;
				}
				$word = strtolower( substr( $s, $i, $j - $i ) );
				$i    = $j;

				if ( isset( self::PACKAGE_PREFIXES[ $word ] ) && $i < $n && '.' === $s[ $i ] ) {
					$j2 = $i + 1;
					while ( $j2 < $n && ( ctype_alnum( $s[ $j2 ] ) || '_' === $s[ $j2 ] ) ) {
						++$j2;
					}
					$i        = $j2;
					$tokens[] = array( 'F', $word );
					++$count;
					continue;
				}

				$k = $i;
				while ( $k < $n && ( ' ' === $s[ $k ] || "\t" === $s[ $k ] || "\r" === $s[ $k ] || "\n" === $s[ $k ] ) ) {
					++$k;
				}
				$isCall = $k < $n && '(' === $s[ $k ];

				if ( $isCall && isset( self::ATTACK_FUNCTIONS[ $word ] ) ) {
					$type = 'F';
				} elseif ( $isCall && isset( self::GENERAL_FUNCTIONS[ $word ] ) ) {
					$type = 'f';
				} elseif ( isset( self::UNION_WORDS[ $word ] ) ) {
					$type = 'U';
				} elseif ( isset( self::STMT_VERBS[ $word ] ) ) {
					$type = 'E';
				} elseif ( isset( self::LOGIC_WORDS[ $word ] ) ) {
					$type = '&';
				} elseif ( isset( self::COMP_WORDS[ $word ] ) ) {
					$type = '=';
				} elseif ( isset( self::CONST_WORDS[ $word ] ) ) {
					$type = '1';
				} elseif ( isset( self::SCHEMA_WORDS[ $word ] ) ) {
					$type = 'I';
				} elseif ( isset( self::CLAUSE_WORDS[ $word ] ) ) {
					$type = 'k';
				} else {
					$type = 'n';
				}
				$tokens[] = array( $type, $word );
				++$count;
				continue;
			}

			// Multi-character operators.
			if ( '<' === $ch && $i + 2 < $n && '=' === $s[ $i + 1 ] && '>' === $s[ $i + 2 ] ) {
				$tokens[] = array( '=', '<=>' );
				++$count;
				$i += 3;
				continue;
			}
			if ( $i + 1 < $n ) {
				$two = $ch . $s[ $i + 1 ];
				if ( '&&' === $two || '||' === $two ) {
					$tokens[] = array( '&', $two );
					++$count;
					$i += 2;
					continue;
				}
				if ( '!=' === $two || '<>' === $two || '<=' === $two || '>=' === $two ) {
					$tokens[] = array( '=', $two );
					++$count;
					$i += 2;
					continue;
				}
				if ( '<<' === $two || '>>' === $two || ':=' === $two ) {
					$tokens[] = array( 'o', $two );
					++$count;
					$i += 2;
					continue;
				}
			}

			// Single-character operators and punctuation.
			if ( '=' === $ch || '<' === $ch || '>' === $ch ) {
				$tokens[] = array( '=', $ch );
				++$count;
				++$i;
				continue;
			}
			if ( false !== strpos( '+-*/%~^|', $ch ) ) {
				$tokens[] = array( 'o', $ch );
				++$count;
				++$i;
				continue;
			}
			if ( '(' === $ch || ')' === $ch || ',' === $ch || ';' === $ch || '.' === $ch ) {
				$tokens[] = array( $ch, $ch );
				++$count;
				++$i;
				continue;
			}

			++$i;
		}

		return $tokens;
	}

	/**
	 * Fold token sequences iteratively and return the first 5 token types.
	 *
	 * @param array<int,array{0:string,1:string}> $tokens
	 */
	public static function fold( array $tokens ) {
		$t    = array();
		$vals = array();
		foreach ( $tokens as $tok ) {
			$t[]    = $tok[0];
			$vals[] = $tok[1];
		}

		$changed = true;
		$iters   = 0;
		while ( $changed && $iters < 20 ) {
			$changed = false;
			++$iters;
			$outT = array();
			$outV = array();
			$outC = 0;
			$i    = 0;
			$m    = count( $t );

			while ( $i < $m ) {
				$cur  = $t[ $i ];
				$curv = $vals[ $i ];

				// Dotted identifiers: n.n -> n, I.n / I.k -> I.
				if ( $i + 2 < $m && '.' === $t[ $i + 1 ] && ( 'n' === $cur || 'I' === $cur || 'k' === $cur ) && ( 'n' === $t[ $i + 2 ] || 'k' === $t[ $i + 2 ] || 'I' === $t[ $i + 2 ] ) ) {
					$outT[]  = ( 'I' === $cur || 'I' === $t[ $i + 2 ] ) ? 'I' : 'n';
					$outV[]  = $curv;
					++$outC;
					$i      += 3;
					$changed = true;
					continue;
				}
				if ( '.' === $cur ) {
					++$i;
					$changed = true;
					continue;
				}
				if ( 'c' === $cur && $outC > 0 && 'c' === $outT[ $outC - 1 ] ) {
					++$i;
					$changed = true;
					continue;
				}
				// UNION ALL / UNION DISTINCT -> U.
				if ( 'U' === $cur && $i + 1 < $m && 'k' === $t[ $i + 1 ] && ( 'all' === $vals[ $i + 1 ] || 'distinct' === $vals[ $i + 1 ] ) ) {
					$outT[]  = 'U';
					$outV[]  = $curv;
					++$outC;
					$i      += 2;
					$changed = true;
					continue;
				}
				// SELECT * -> E.
				if ( 'E' === $cur && 'select' === $curv && $i + 1 < $m && 'o' === $t[ $i + 1 ] && '*' === $vals[ $i + 1 ] ) {
					$outT[]  = 'E';
					$outV[]  = $curv;
					++$outC;
					$i      += 2;
					$changed = true;
					continue;
				}
				// Unary +, -, ~ before 1 / f / F.
				if ( 'o' === $cur && ( '+' === $curv || '-' === $curv || '~' === $curv ) && $i + 1 < $m && ( '1' === $t[ $i + 1 ] || 'f' === $t[ $i + 1 ] || 'F' === $t[ $i + 1 ] ) ) {
					$prev = $outC > 0 ? $outT[ $outC - 1 ] : '';
					if ( '' === $prev || false !== strpos( '(,=&EkoU;', $prev ) ) {
						$outT[]  = $t[ $i + 1 ];
						$outV[]  = $vals[ $i + 1 ];
						++$outC;
						$i      += 2;
						$changed = true;
						continue;
					}
				}
				// Adjacent string literals.
				if ( 's' === $cur && $outC > 0 && 's' === $outT[ $outC - 1 ] ) {
					++$i;
					$changed = true;
					continue;
				}
				// Balanced function call f(...) / F(...) without embedded subquery -> f / F.
				if ( ( 'f' === $cur || 'F' === $cur ) && $i + 1 < $m && '(' === $t[ $i + 1 ] ) {
					$depth       = 1;
					$j           = $i + 2;
					$hasSubquery = false;
					$hasAttackFn = 'F' === $cur;
					while ( $j < $m && $depth > 0 ) {
						if ( '(' === $t[ $j ] ) {
							++$depth;
						} elseif ( ')' === $t[ $j ] ) {
							--$depth;
						} elseif ( 'E' === $t[ $j ] || 'U' === $t[ $j ] ) {
							$hasSubquery = true;
						} elseif ( 'F' === $t[ $j ] ) {
							$hasAttackFn = true;
						}
						++$j;
					}
					if ( 0 === $depth && ! $hasSubquery ) {
						$outT[]  = $hasAttackFn ? 'F' : 'f';
						$outV[]  = $curv;
						++$outC;
						$i       = $j;
						$changed = true;
						continue;
					}
				}
				// Parenthesised single atom (1), (s), (f), (F), (v), (n) not after f/F/n.
				if ( '(' === $cur && $i + 2 < $m && ')' === $t[ $i + 2 ] && false !== strpos( '1sfFvn', $t[ $i + 1 ] ) ) {
					$prev = $outC > 0 ? $outT[ $outC - 1 ] : '';
					if ( 'f' !== $prev && 'F' !== $prev && 'n' !== $prev ) {
						$outT[]  = $t[ $i + 1 ];
						$outV[]  = $vals[ $i + 1 ];
						++$outC;
						$i      += 3;
						$changed = true;
						continue;
					}
				}
				// Arithmetic folding: 1 o 1 -> 1 (preserving F/f/v priority).
				if ( $i + 2 < $m && 'o' === $t[ $i + 1 ] && false !== strpos( '1fFv', $cur ) && false !== strpos( '1fFv', $t[ $i + 2 ] ) ) {
					$rhs = $t[ $i + 2 ];
					if ( 'F' === $cur || 'F' === $rhs ) {
						$nt = 'F';
					} elseif ( 'f' === $cur || 'f' === $rhs ) {
						$nt = 'f';
					} elseif ( 'v' === $cur || 'v' === $rhs ) {
						$nt = 'v';
					} else {
						$nt = '1';
					}
					$outT[]  = $nt;
					$outV[]  = $curv;
					++$outC;
					$i      += 3;
					$changed = true;
					continue;
				}
				// Comma-separated lists: 1,1 -> 1, s,s -> s, n,n -> n, or mixed after SELECT/clause.
				if ( $i + 2 < $m && ',' === $t[ $i + 1 ] && false !== strpos( '1snfFv', $cur ) && false !== strpos( '1snfFv', $t[ $i + 2 ] ) ) {
					$rhs = $t[ $i + 2 ];
					if ( $cur === $rhs || ( $outC > 0 && ( 'E' === $outT[ $outC - 1 ] || 'k' === $outT[ $outC - 1 ] ) ) ) {
						if ( 'F' === $cur || 'F' === $rhs ) {
							$nt = 'F';
						} elseif ( 'f' === $cur || 'f' === $rhs ) {
							$nt = 'f';
						} else {
							$nt = $cur;
						}
						$outT[]  = $nt;
						$outV[]  = $curv;
						++$outC;
						$i      += 3;
						$changed = true;
						continue;
					}
				}
				// Adjacent clause keywords: ORDER BY, GROUP BY, INTO OUTFILE, IS NOT, NOT IN.
				if ( 'k' === $cur && $outC > 0 && 'k' === $outT[ $outC - 1 ] ) {
					++$i;
					$changed = true;
					continue;
				}
				if ( 'k' === $cur && ( 'not' === $curv || 'is' === $curv ) && $i + 1 < $m && '=' === $t[ $i + 1 ] ) {
					$outT[]  = '=';
					$outV[]  = '=';
					++$outC;
					$i      += 2;
					$changed = true;
					continue;
				}
				if ( 'k' === $cur && 'is' === $curv && $i + 1 < $m && '1' === $t[ $i + 1 ] ) {
					$outT[]  = '=';
					$outV[]  = '=';
					$outT[]  = '1';
					$outV[]  = $vals[ $i + 1 ];
					$outC   += 2;
					$i      += 2;
					$changed = true;
					continue;
				}

				$outT[] = $cur;
				$outV[] = $curv;
				++$outC;
				++$i;
			}
			$t    = $outT;
			$vals = $outV;
		}

		return implode( '', array_slice( $t, 0, 5 ) );
	}
}

<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Waf\Engine;
use WordGate\Waf\Request;
use WordGate\Waf\Rule;
use WordGate\Waf\SqliTokenizer;
use WordGate\Waf\Storage;

final class SqliTokenizerTest extends TestCase {

	public function testDetectsFullSqliCorpus() {
		$payloads = file( __DIR__ . '/../fixtures/sqli/payloads.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		$this->assertGreaterThanOrEqual( 1000, count( $payloads ) );

		$missed = array();
		foreach ( $payloads as $payload ) {
			if ( null === SqliTokenizer::detect( $payload ) ) {
				$missed[] = $payload;
			}
		}
		$this->assertSame(
			array(),
			array_slice( $missed, 0, 10 ),
			sprintf( 'Missed %d of %d SQLi payloads', count( $missed ), count( $payloads ) )
		);
	}

	public function testZeroFalsePositivesOnBenignCorpus() {
		$benign = file( __DIR__ . '/../fixtures/sqli/benign.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		$this->assertGreaterThanOrEqual( 500, count( $benign ) );

		$falsePositives = array();
		foreach ( $benign as $sample ) {
			$hit = SqliTokenizer::detect( $sample );
			if ( null !== $hit ) {
				$falsePositives[] = $hit['fingerprint'] . ' (' . $hit['context'] . ') on: ' . $sample;
			}
		}
		$this->assertSame(
			array(),
			array_slice( $falsePositives, 0, 10 ),
			sprintf( 'Found %d false positives in %d benign samples', count( $falsePositives ), count( $benign ) )
		);
	}

	public function testRuleTypeSqliBlocksNovelPayloadsEvadingRegexRules() {
		$dir     = WORDGATE_TEST_DATA_DIR . '/' . uniqid( 'sqli_rule', true );
		$storage = new Storage( $dir );
		$storage->ensureDir();
		$rules  = $storage->loadRules( __DIR__ . '/../../waf/rules/default.json' );
		$engine = new Engine( $storage, array(), $rules );

		// Payloads not covered by regex rules 1001–1005, caught by rule 1006 (type=sqli).
		$novel = array(
			"1' HAVING 1=1--",
			"1' ORDER BY 100--",
			"1' AND (SELECT COUNT(*) FROM wp_users)>0--",
			"1' AND ASCII(SUBSTRING((SELECT user_pass FROM wp_users LIMIT 1),1,1))>64--",
			"1'; EXEC xp_cmdshell('whoami')--",
		);
		foreach ( $novel as $p ) {
			$req = new Request( '203.0.113.10', 'GET', '/?id=' . rawurlencode( $p ), array( 'id' => $p ) );
			$dec = $engine->inspect( $req );
			$this->assertSame( Engine::BLOCK, $dec['action'], 'Expected block for: ' . $p );
			$this->assertSame( 1006, $dec['rule']->id, 'Expected rule 1006 for: ' . $p );
			$this->assertArrayHasKey( 'fingerprint', $dec['match'] );
		}

		// Explicit standalone type=sqli Rule works even without a regex pattern.
		$rule = new Rule(
			array(
				'id'      => 9999,
				'name'    => 'Standalone SQLi tokenizer',
				'type'    => 'sqli',
				'targets' => array( 'query' ),
			)
		);
		$this->assertTrue( $rule->isValid() );
		$hit = $rule->evaluate( new Request( '203.0.113.10', 'GET', '/', array( 'q' => "admin' OR '1'='1" ) ) );
		$this->assertNotNull( $hit );
		$this->assertSame( 's&s=s', $hit['fingerprint'] );
	}

	public function testPerformanceUnderPointTwoMillisecondsPerParameter() {
		$benign = file( __DIR__ . '/../fixtures/sqli/benign.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES );
		// Warm up static fingerprint cache.
		SqliTokenizer::detect( "admin' OR '1'='1" );

		$iterations = count( $benign );
		$start      = microtime( true );
		foreach ( $benign as $sample ) {
			SqliTokenizer::detect( $sample );
		}
		$elapsedMs = ( microtime( true ) - $start ) * 1000;
		$perParam  = $elapsedMs / max( 1, $iterations );

		$this->assertLessThan(
			0.2,
			$perParam,
			sprintf( 'Average %.4f ms/param exceeded 0.2 ms budget (%d samples in %.2f ms)', $perParam, $iterations, $elapsedMs )
		);
	}
}

<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Login\BruteForce;
use WordGate\Waf\Storage;

final class PasswordResetTest extends TestCase {

	/** @var Storage */
	private $storage;

	protected function setUp(): void {
		$dir = WORDGATE_TEST_DATA_DIR . '/' . uniqid( 'pwreset', true );
		$this->storage = new Storage( $dir );
		$this->storage->ensureDir();
	}

	public function testPerIpLimitEnforced() {
		$ip = '198.51.100.42';
		for ( $i = 1; $i <= 5; $i++ ) {
			$r = BruteForce::checkLostPasswordRate( $this->storage, $ip, 0, 5 );
			$this->assertSame( 'allow', $r['status'] );
			$this->assertSame( $i, $r['ip_count'] );
		}
		$r = BruteForce::checkLostPasswordRate( $this->storage, $ip, 0, 5 );
		$this->assertSame( 'ip_limit', $r['status'] );
		$this->assertSame( 6, $r['ip_count'] );
	}

	public function testPerUserLimitStopsDistributedFlood() {
		// Six different IPs targeting the same user ID (7) within an hour.
		for ( $i = 1; $i <= 5; $i++ ) {
			$r = BruteForce::checkLostPasswordRate( $this->storage, '203.0.113.' . $i, 7, 5 );
			$this->assertSame( 'allow', $r['status'] );
			$this->assertSame( $i, $r['user_count'] );
		}
		$r = BruteForce::checkLostPasswordRate( $this->storage, '203.0.113.99', 7, 5 );
		$this->assertSame( 'user_limit', $r['status'] );
		$this->assertSame( 6, $r['user_count'] );
	}

	public function testAllowlistedIpSkipsIpLimitButStillRespectsPerUserCap() {
		$ip = '192.0.2.10';
		for ( $i = 1; $i <= 5; $i++ ) {
			$r = BruteForce::checkLostPasswordRate( $this->storage, $ip, 0, 5, true );
			$this->assertSame( 'allow', $r['status'] );
			$this->assertSame( 0, $r['ip_count'] );
		}
		$r = BruteForce::checkLostPasswordRate( $this->storage, $ip, 0, 5, true );
		$this->assertSame( 'allow', $r['status'] );

		// Per-user flood protection still applies.
		for ( $i = 1; $i <= 3; $i++ ) {
			$this->assertSame( 'allow', BruteForce::checkLostPasswordRate( $this->storage, $ip, 12, 3, true )['status'] );
		}
		$this->assertSame( 'user_limit', BruteForce::checkLostPasswordRate( $this->storage, $ip, 12, 3, true )['status'] );
	}

	public function testZeroLimitDisablesRateLimiting() {
		for ( $i = 0; $i < 10; $i++ ) {
			$this->assertSame( 'allow', BruteForce::checkLostPasswordRate( $this->storage, '198.51.100.77', 9, 0 )['status'] );
		}
	}
}

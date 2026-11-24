<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\TamperMonitor;
use WordGate\Waf\Storage;

final class TamperMonitorTest extends TestCase {

	public function testDiffSettingsDetectsOnlyChangedKeys() {
		$before = array( 'waf_mode' => 'enabled', 'bf_max_failures' => 5, 'notify_tamper' => true );
		$after  = array( 'waf_mode' => 'disabled', 'bf_max_failures' => 5, 'notify_tamper' => false );
		$this->assertSame( array( 'notify_tamper', 'waf_mode' ), TamperMonitor::diffSettings( $before, $after ) );
		$this->assertSame( array(), TamperMonitor::diffSettings( $before, $before ) );
	}

	public function testEvaluateWafHealthCleanWhenHealthy() {
		$alerts = TamperMonitor::evaluateWafHealth( 'extended', array( 'mode' => 'extended' ), 'enabled', false, 120 );
		$this->assertSame( array(), $alerts );
	}

	public function testEvaluateWafHealthSilentWhenModeDisabled() {
		$alerts = TamperMonitor::evaluateWafHealth( 'extended', array( 'mode' => 'none' ), 'disabled', true, 999999 );
		$this->assertSame( array(), $alerts );
	}

	public function testEvaluateWafHealthDetectsPrependRemovedLoaderRemovedKillSwitchAndStaleHeartbeat() {
		$types = array_column(
			TamperMonitor::evaluateWafHealth( 'extended', array( 'mode' => 'basic' ), 'enabled', false, 60 ),
			'type'
		);
		$this->assertSame( array( 'waf_prepend_removed' ), $types );

		$types = array_column(
			TamperMonitor::evaluateWafHealth( 'basic', array( 'mode' => 'none' ), 'enabled', false, null ),
			'type'
		);
		$this->assertSame( array( 'waf_loader_removed' ), $types );

		$types = array_column(
			TamperMonitor::evaluateWafHealth( 'extended', array( 'mode' => 'extended' ), 'enabled', true, 999999 ),
			'type'
		);
		$this->assertSame( array( 'waf_kill_switch' ), $types );

		$types = array_column(
			TamperMonitor::evaluateWafHealth( 'extended', array( 'mode' => 'extended' ), 'enabled', false, 30000, 21600 ),
			'type'
		);
		$this->assertSame( array( 'waf_heartbeat_stale' ), $types );
	}

	public function testHeartbeatWriteAndAge() {
		$dir     = WORDGATE_TEST_DATA_DIR . '/' . uniqid( 'hb', true );
		$storage = new Storage( $dir );
		$storage->ensureDir();

		$this->assertNull( $storage->heartbeatAge() );
		$this->assertTrue( $storage->touchHeartbeat( 300, 1700000000 ) );
		$this->assertSame( 500, $storage->heartbeatAge( 1700000500 ) );
		// Throttled within 300s interval (uses filemtime which is now, so passing time() returns false).
		$this->assertFalse( $storage->touchHeartbeat( 300 ) );
	}
}

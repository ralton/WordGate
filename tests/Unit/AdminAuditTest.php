<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Scanner\AdminAudit;

final class AdminAuditTest extends TestCase {

	private function admin( $id, $login, array $roles = array( 'administrator' ), array $caps = array( 'administrator' => true ) ) {
		return array(
			'id'         => $id,
			'login'      => $login,
			'email'      => $login . '@example.com',
			'registered' => '2026-01-01 00:00:00',
			'roles'      => $roles,
			'caps'       => $caps,
		);
	}

	public function testFirstScanEstablishesBaselineWithoutFalseAlarms() {
		$current = array(
			1 => $this->admin( 1, 'jane' ),
			2 => $this->admin( 2, 'bob' ),
		);
		$result = AdminAudit::audit( null, $current, array(), array( 1, 2 ) );
		$this->assertTrue( $result['baseline_created'] );
		$this->assertSame( array(), $result['findings'] );
		$this->assertSame( $current, AdminAudit::nextSnapshot( null, $current ) );
	}

	public function testDirectDbInsertedAdminFlaggedHigh() {
		$prev    = array( 1 => $this->admin( 1, 'jane' ) );
		$current = array(
			1 => $this->admin( 1, 'jane' ),
			9 => $this->admin( 9, 'stealth' ),
		);
		$result = AdminAudit::audit( $prev, $current, array(), array( 1, 9 ) );
		$this->assertFalse( $result['baseline_created'] );
		$this->assertCount( 1, $result['findings'] );
		$this->assertSame( 'suspicious_admin', $result['findings'][0]['type'] );
		$this->assertSame( 'high', $result['findings'][0]['severity'] );

		// Untrusted new admin is NOT absorbed into next snapshot until explicitly trusted.
		$next = AdminAudit::nextSnapshot( $prev, $current );
		$this->assertArrayNotHasKey( 9, $next );
		// Once trusted (ignored), it joins the baseline.
		$nextTrusted = AdminAudit::nextSnapshot( $prev, $current, array( 9 ) );
		$this->assertArrayHasKey( 9, $nextTrusted );
	}

	public function testLoggedAdminCreationByExistingAdminIsInfoOnly() {
		$prev    = array( 1 => $this->admin( 1, 'jane' ) );
		$current = array(
			1 => $this->admin( 1, 'jane' ),
			5 => $this->admin( 5, 'alex' ),
		);
		$logged  = array( 5 => array( 'actor' => 'jane (#1)', 'actor_id' => 1 ) );
		$result  = AdminAudit::audit( $prev, $current, $logged, array( 1, 5 ) );
		$this->assertCount( 1, $result['findings'] );
		$this->assertSame( 'admin_added', $result['findings'][0]['type'] );
		$this->assertSame( 'info', $result['findings'][0]['severity'] );
	}

	public function testDetectsCapabilityWithoutRoleKnownBadNameAndHiddenAdmin() {
		$prev    = array( 1 => $this->admin( 1, 'jane' ) );
		$current = array(
			1 => $this->admin( 1, 'jane' ),
			2 => $this->admin( 2, 'ghost', array(), array( 'manage_options' => true ) ),
			3 => $this->admin( 3, 'wp_admin_support' ),
		);
		// User 3 is missing from get_users() visible list -> hidden admin!
		$result = AdminAudit::audit( $prev, $current, array(), array( 1, 2 ) );
		$types  = array_column( $result['findings'], 'type' );
		$sevs   = array_column( $result['findings'], 'severity', 'type' );

		$this->assertContains( 'admin_no_role', $types );
		$this->assertSame( 'high', $sevs['admin_no_role'] );

		$this->assertContains( 'suspicious_admin_name', $types );
		$this->assertSame( 'high', $sevs['suspicious_admin_name'] );

		$this->assertContains( 'hidden_admin_user', $types );
		$this->assertSame( 'critical', $sevs['hidden_admin_user'] );
	}
}

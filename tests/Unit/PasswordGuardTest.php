<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Login\PasswordGuard;

final class PasswordGuardTest extends TestCase {

	public function testCommonPasswordsDetectedLocallyWithoutRemoteCall() {
		$called = false;
		$http   = static function () use ( &$called ) {
			$called = true;
			return '';
		};

		$res = PasswordGuard::evaluate( 'Password123', true, $http );
		$this->assertTrue( $res['compromised'] );
		$this->assertSame( 'common', $res['source'] );
		$this->assertFalse( $called, 'Common password must be caught locally without hitting HIBP' );
	}

	public function testHibpSendsOnlyFiveCharSha1PrefixAndAddPaddingHeader() {
		// Use a password not in the bundled common list so HIBP is called.
		$password = 'correct-horse-battery-staple-test-99';
		$sha1     = strtoupper( sha1( $password ) );
		$prefix   = substr( $sha1, 0, 5 );
		$suffix   = substr( $sha1, 5 );

		$capturedUrl     = '';
		$capturedHeaders = array();
		$http            = static function ( $url, $headers ) use ( &$capturedUrl, &$capturedHeaders, $suffix ) {
			$capturedUrl     = $url;
			$capturedHeaders = $headers;
			return "00000000000000000000000000000000000:0\r\n{$suffix}:4219\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\r\n";
		};

		$res = PasswordGuard::evaluate( $password, true, $http );
		$this->assertSame( 'https://api.pwnedpasswords.com/range/' . $prefix, $capturedUrl );
		$this->assertStringNotContainsString( $suffix, $capturedUrl );
		$this->assertStringNotContainsString( $password, $capturedUrl );
		$this->assertSame( 'true', $capturedHeaders['Add-Padding'] );
		$this->assertTrue( $res['compromised'] );
		$this->assertSame( 'hibp', $res['source'] );
		$this->assertSame( 4219, $res['count'] );
	}

	public function testHibpIgnoresPaddedZeroCounts() {
		$password = 'unique-unbreached-passphrase-2026-xyz';
		$suffix   = substr( strtoupper( sha1( $password ) ), 5 );
		$http     = static function () use ( $suffix ) {
			return "{$suffix}:0\r\n";
		};
		$res = PasswordGuard::evaluate( $password, true, $http );
		$this->assertFalse( $res['compromised'] );
		$this->assertSame( 'clean', $res['source'] );
	}

	public function testHibpFailsOpenWhenUnreachable() {
		$http = static function () {
			return null;
		};
		$res = PasswordGuard::evaluate( 'some-long-uncommon-passphrase-777', true, $http );
		$this->assertFalse( $res['compromised'] );
		$this->assertSame( 'clean', $res['source'] );
	}

	public function testDisablingRemoteCheckSkipsHibp() {
		$called = false;
		$http   = static function () use ( &$called ) {
			$called = true;
			return '';
		};
		$res = PasswordGuard::evaluate( 'some-long-uncommon-passphrase-777', false, $http );
		$this->assertFalse( $called );
		$this->assertFalse( $res['compromised'] );
	}

	public function testRoleEnforcementPolicy() {
		$this->assertTrue( PasswordGuard::shouldEnforce( array( 'administrator' ), array( 'administrator', 'editor' ) ) );
		$this->assertFalse( PasswordGuard::shouldEnforce( array( 'subscriber' ), array( 'administrator', 'editor' ) ) );
		$this->assertFalse( PasswordGuard::shouldEnforce( array( 'administrator' ), array() ) );
	}
}

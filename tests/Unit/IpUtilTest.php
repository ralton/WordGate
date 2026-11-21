<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Waf\IpUtil;

final class IpUtilTest extends TestCase {

	public function testIpv4Cidr() {
		$this->assertTrue( IpUtil::inRange( '10.1.2.3', '10.0.0.0/8' ) );
		$this->assertTrue( IpUtil::inRange( '192.168.1.255', '192.168.1.0/24' ) );
		$this->assertFalse( IpUtil::inRange( '192.168.2.1', '192.168.1.0/24' ) );
		$this->assertTrue( IpUtil::inRange( '172.16.5.4', '172.16.0.0/12' ) );
		$this->assertFalse( IpUtil::inRange( '172.32.0.1', '172.16.0.0/12' ) );
		$this->assertTrue( IpUtil::inRange( '1.2.3.4', '0.0.0.0/0' ) );
		$this->assertTrue( IpUtil::inRange( '1.2.3.4', '1.2.3.4' ) );
	}

	public function testIpv6Cidr() {
		$this->assertTrue( IpUtil::inRange( '2001:db8::1', '2001:db8::/32' ) );
		$this->assertFalse( IpUtil::inRange( '2001:db9::1', '2001:db8::/32' ) );
		$this->assertTrue( IpUtil::inRange( '2001:db8:0:0:0:0:0:1', '2001:db8::1' ) );
	}

	public function testMappedIpv4() {
		$this->assertSame( '1.2.3.4', IpUtil::normalize( '::ffff:1.2.3.4' ) );
		$this->assertTrue( IpUtil::inRange( '::ffff:10.0.0.1', '10.0.0.0/8' ) );
	}

	public function testValidation() {
		$this->assertTrue( IpUtil::isValidRange( '10.0.0.0/8' ) );
		$this->assertFalse( IpUtil::isValidRange( '10.0.0.0/33' ) );
		$this->assertFalse( IpUtil::isValidRange( 'example.com' ) );
		$this->assertTrue( IpUtil::isValidRange( '2001:db8::/128' ) );
	}

	public function testForwardedHeaderIgnoredWithoutTrustedProxy() {
		$server = array( 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6' );
		$this->assertSame( '203.0.113.9', IpUtil::clientIp( $server, 'HTTP_X_FORWARDED_FOR', array() ) );
		$this->assertSame( '203.0.113.9', IpUtil::clientIp( $server, 'HTTP_X_FORWARDED_FOR', array( '10.0.0.0/8' ) ) );
	}

	public function testForwardedHeaderFromTrustedProxy() {
		$server = array( 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 198.51.100.7, 10.0.0.2' );
		// Right-most untrusted hop wins; the spoofable left-most value is ignored.
		$this->assertSame( '198.51.100.7', IpUtil::clientIp( $server, 'HTTP_X_FORWARDED_FOR', array( '10.0.0.0/8' ) ) );
	}
}

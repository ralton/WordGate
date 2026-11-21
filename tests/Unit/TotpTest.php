<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Login\Totp;

final class TotpTest extends TestCase {

	/** RFC 6238 Appendix B shared secret "12345678901234567890". */
	private function rfcSecret() {
		return Totp::base32Encode( '12345678901234567890' );
	}

	/**
	 * RFC 6238 test vectors (SHA-1, 8 digits).
	 *
	 * @dataProvider vectors
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('vectors')]
	public function testRfcVectors( $time, $expected ) {
		$this->assertSame( $expected, Totp::code( $this->rfcSecret(), intdiv( $time, 30 ), 8 ) );
	}

	public static function vectors() {
		return array(
			array( 59, '94287082' ),
			array( 1111111109, '07081804' ),
			array( 1111111111, '14050471' ),
			array( 1234567890, '89005924' ),
			array( 2000000000, '69279037' ),
			array( 20000000000, '65353130' ),
		);
	}

	public function testBase32RoundTrip() {
		$raw = random_bytes( 20 );
		$this->assertSame( $raw, Totp::base32Decode( Totp::base32Encode( $raw ) ) );
		$this->assertSame( 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $this->rfcSecret() );
	}

	public function testVerifyWithDriftAndReplay() {
		$secret = Totp::generateSecret();
		$now    = 1700000000;
		$step   = intdiv( $now, 30 );
		$prev   = Totp::code( $secret, $step - 1 );

		$this->assertSame( $step, Totp::verify( $secret, Totp::code( $secret, $step ), 1, $now ) );
		$this->assertSame( $step - 1, Totp::verify( $secret, $prev, 1, $now ) );
		$this->assertFalse( Totp::verify( $secret, Totp::code( $secret, $step - 3 ), 1, $now ) );
		// Replay of an already used step is refused.
		$this->assertFalse( Totp::verify( $secret, $prev, 1, $now, $step - 1 ) );
		$this->assertFalse( Totp::verify( $secret, 'abcdef', 1, $now ) );
		$this->assertSame( $step, Totp::verify( $secret, substr( Totp::code( $secret, $step ), 0, 3 ) . ' ' . substr( Totp::code( $secret, $step ), 3 ), 1, $now ) );
	}

	public function testProvisioningUri() {
		$uri = Totp::provisioningUri( 'ABC', 'jane@example.com', 'My Site' );
		$this->assertStringStartsWith( 'otpauth://totp/My%20Site:jane%40example.com?secret=ABC&issuer=My%20Site', $uri );
	}
}

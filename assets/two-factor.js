/* global WordGate2FA, qrcode */
( function () {
	'use strict';
	var box = document.getElementById( 'wordgate-2fa-box' );
	if ( ! box || typeof WordGate2FA === 'undefined' ) {
		return;
	}
	var msg = document.getElementById( 'wordgate-2fa-msg' );

	function post( action, data ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', WordGate2FA.nonce );
		body.append( 'user_id', WordGate2FA.userId );
		Object.keys( data || {} ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( WordGate2FA.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}

	function say( text, isError ) {
		msg.textContent = text || '';
		msg.style.color = isError ? '#d63638' : '';
	}

	function showCodes( codes ) {
		var pre = document.getElementById( 'wordgate-2fa-codes' );
		pre.textContent = WordGate2FA.i18n.saveCodes + '\n\n' + codes.join( '\n' );
		pre.hidden = false;
	}

	function on( id, fn ) {
		var el = document.getElementById( id );
		if ( el ) {
			el.addEventListener( 'click', fn );
		}
	}

	function currentPassword() {
		var el = document.getElementById( 'wordgate-2fa-password' );
		return el ? el.value : '';
	}

	on( 'wordgate-2fa-begin', function () {
		post( 'wordgate_2fa_begin' ).then( function ( res ) {
			if ( ! res.success ) {
				return say( ( res.data && res.data.message ) || WordGate2FA.i18n.error, true );
			}
			var qr = qrcode( 0, 'M' );
			qr.addData( res.data.uri );
			qr.make();
			document.getElementById( 'wordgate-2fa-qr' ).innerHTML = qr.createSvgTag( { cellSize: 4, margin: 4, scalable: false } );
			document.getElementById( 'wordgate-2fa-secret' ).textContent = res.data.secret;
			document.getElementById( 'wordgate-2fa-setup' ).hidden = false;
			document.getElementById( 'wordgate-2fa-begin' ).style.display = 'none';
			document.getElementById( 'wordgate-2fa-code' ).focus();
		} );
	} );

	on( 'wordgate-2fa-enable', function () {
		var code = document.getElementById( 'wordgate-2fa-code' ).value;
		post( 'wordgate_2fa_enable', { code: code } ).then( function ( res ) {
			if ( ! res.success ) {
				return say( ( res.data && res.data.message ) || WordGate2FA.i18n.error, true );
			}
			document.getElementById( 'wordgate-2fa-setup' ).hidden = true;
			say( WordGate2FA.i18n.enabled );
			showCodes( res.data.codes );
		} );
	} );

	on( 'wordgate-2fa-disable', function () {
		var password = currentPassword();
		if ( WordGate2FA.isSelf && ! password ) {
			return say( WordGate2FA.i18n.passwordMissing, true );
		}
		if ( ! window.confirm( WordGate2FA.i18n.confirmDisable ) ) {
			return;
		}
		post( 'wordgate_2fa_disable', { password: password } ).then( function ( res ) {
			if ( ! res.success ) {
				return say( ( res.data && res.data.message ) || WordGate2FA.i18n.error, true );
			}
			window.location.reload();
		} );
	} );

	on( 'wordgate-2fa-recovery', function () {
		var password = currentPassword();
		if ( ! password ) {
			return say( WordGate2FA.i18n.passwordMissing, true );
		}
		post( 'wordgate_2fa_recovery', { password: password } ).then( function ( res ) {
			if ( ! res.success ) {
				return say( ( res.data && res.data.message ) || WordGate2FA.i18n.error, true );
			}
			say( '' );
			showCodes( res.data.codes );
		} );
	} );

	// Keep the profile form's Enter key from submitting while typing a code.
	var input = document.getElementById( 'wordgate-2fa-code' );
	if ( input ) {
		input.addEventListener( 'keydown', function ( e ) {
			if ( e.key === 'Enter' ) {
				e.preventDefault();
				document.getElementById( 'wordgate-2fa-enable' ).click();
			}
		} );
	}
}() );

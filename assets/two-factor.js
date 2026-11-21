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

	on( 'wordgate-2fa-begin', function () {
		post( 'wordgate_2fa_begin' ).then( function ( res ) {
			if ( ! res.success ) {
				return say( 'Error', true );
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
				return say( res.data && res.data.message, true );
			}
			document.getElementById( 'wordgate-2fa-setup' ).hidden = true;
			say( '✓ Two-factor authentication is on.' );
			showCodes( res.data.codes );
		} );
	} );

	on( 'wordgate-2fa-disable', function () {
		if ( ! window.confirm( WordGate2FA.i18n.confirmDisable ) ) {
			return;
		}
		post( 'wordgate_2fa_disable' ).then( function () {
			window.location.reload();
		} );
	} );

	on( 'wordgate-2fa-recovery', function () {
		post( 'wordgate_2fa_recovery' ).then( function ( res ) {
			if ( res.success ) {
				showCodes( res.data.codes );
			}
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

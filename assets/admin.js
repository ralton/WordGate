/* global WordGateAdmin */
( function () {
	'use strict';

	// Confirm destructive actions.
	document.querySelectorAll( '.wg-confirm-delete' ).forEach( function ( a ) {
		a.addEventListener( 'click', function ( e ) {
			if ( ! window.confirm( WordGateAdmin.i18n.confirmDelete ) ) {
				e.preventDefault();
			}
		} );
	} );

	// Scanner progress.
	var btn = document.getElementById( 'wg-scan-start' );
	if ( ! btn ) {
		return;
	}
	var box = document.getElementById( 'wg-scan-progress' );
	var bar = box.querySelector( '.wg-progress span' );
	var phase = document.getElementById( 'wg-scan-phase' );

	function call( action ) {
		var body = new FormData();
		body.append( 'action', action );
		body.append( 'nonce', WordGateAdmin.scanNonce );
		return fetch( WordGateAdmin.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}

	function render( s ) {
		box.hidden = false;
		var pct = Math.round( ( s.index / s.total ) * 100 );
		if ( s.phase && s.stats && s.stats.files_total && s.index === 4 ) {
			pct += Math.round( ( s.stats.files_scanned / s.stats.files_total ) * ( 100 / s.total ) );
		}
		bar.style.width = Math.min( 100, pct ) + '%';
		var text = s.phase || '';
		if ( s.stats && s.stats.files_total && s.index >= 4 ) {
			text += ' — ' + s.stats.files_scanned.toLocaleString() + ' / ' + s.stats.files_total.toLocaleString() + ' files';
		}
		if ( s.stats ) {
			text += ' · ' + s.stats.issues + ' issues';
		}
		phase.textContent = text;
	}

	function loop( res ) {
		if ( ! res || ! res.success ) {
			phase.textContent = WordGateAdmin.i18n.failed;
			btn.disabled = false;
			return;
		}
		render( res.data );
		if ( res.data.status === 'running' ) {
			call( 'wordgate_scan_step' ).then( loop ).catch( function () {
				setTimeout( function () {
					call( 'wordgate_scan_step' ).then( loop );
				}, 3000 );
			} );
		} else if ( res.data.status === 'done' ) {
			bar.style.width = '100%';
			phase.textContent = WordGateAdmin.i18n.done;
			setTimeout( function () {
				window.location.reload();
			}, 800 );
		} else {
			phase.textContent = WordGateAdmin.i18n.failed + ' ' + ( res.data.notes || [] ).join( ' ' );
			btn.disabled = false;
		}
	}

	btn.addEventListener( 'click', function () {
		btn.disabled = true;
		box.hidden = false;
		call( 'wordgate_scan_start' ).then( loop );
	} );

	// Resume watching a scan that is already running.
	if ( btn.dataset.running === '1' ) {
		call( 'wordgate_scan_step' ).then( loop );
	}
}() );

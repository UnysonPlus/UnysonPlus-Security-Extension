/* Two-factor enrolment on the profile screen. The QR code is drawn here, in the
 * browser, from the otpauth URI: the secret is never sent to another service. */
( function ( $ ) {
	'use strict';

	$( function () {
		var $box = $( '.upw-2fa' );
		if ( ! $box.length ) {
			return;
		}
		var user  = $box.data( 'user' );
		var nonce = $box.data( 'nonce' );
		var $msg  = $box.find( '.upw-2fa-msg' );
		var t     = window.upwSec2fa || {};

		function say( text, isError ) {
			$msg.text( text || '' ).toggleClass( 'is-error', !! isError );
		}

		function post( op, data ) {
			return $.post( window.ajaxurl, $.extend( { action: 'upw_sec_2fa_' + op, user_id: user, nonce: nonce }, data || {} ) )
				.then( function ( r ) {
					if ( r && r.success ) {
						return r.data || {};
					}
					return $.Deferred().reject( ( r && r.data && r.data.message ) || t.failed ).promise();
				}, function ( xhr ) {
					var m = xhr && xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message;
					return $.Deferred().reject( m || t.failed ).promise();
				} );
		}

		function drawQr( uri ) {
			var qr = window.qrcode( 0, 'M' );
			qr.addData( uri );
			qr.make();
			$box.find( '.upw-2fa-qr' ).html( qr.createSvgTag( { cellSize: 5, margin: 4, scalable: true } ) );
		}

		function showCodes( codes ) {
			$box.find( '.upw-2fa-code-list' ).text( codes.join( '\n' ) );
			$box.find( '.upw-2fa-setup' ).prop( 'hidden', true );
			$box.find( '.upw-2fa-codes-out' ).prop( 'hidden', false );
		}

		// Enter in these fields must not submit the whole profile form.
		$box.on( 'keydown', 'input', function ( e ) {
			if ( 13 === e.which ) {
				e.preventDefault();
				$( this ).nextAll( 'button' ).first().trigger( 'click' );
			}
		} );

		$box.on( 'click', '.upw-2fa-start', function () {
			var $btn = $( this ).prop( 'disabled', true );
			say( '' );
			post( 'start' ).then( function ( d ) {
				drawQr( d.uri );
				$box.find( '.upw-2fa-secret' ).text( d.secret );
				$box.find( '.upw-2fa-setup' ).prop( 'hidden', false );
				$btn.closest( 'p' ).prop( 'hidden', true );
				$box.find( '.upw-2fa-confirm-code' ).trigger( 'focus' );
			}, function ( m ) {
				$btn.prop( 'disabled', false );
				say( m, true );
			} );
		} );

		$box.on( 'click', '.upw-2fa-confirm', function () {
			var $btn = $( this ).prop( 'disabled', true );
			say( '' );
			post( 'confirm', { code: $box.find( '.upw-2fa-confirm-code' ).val() } ).then( function ( d ) {
				showCodes( d.codes );
				say( t.on );
			}, function ( m ) {
				$btn.prop( 'disabled', false );
				say( m, true );
			} );
		} );

		$box.on( 'click', '.upw-2fa-codes', function () {
			say( '' );
			post( 'codes', { code: $box.find( '.upw-2fa-current' ).val() } ).then( function ( d ) {
				showCodes( d.codes );
				say( t.newCodes );
			}, function ( m ) {
				say( m, true );
			} );
		} );

		$box.on( 'click', '.upw-2fa-disable', function () {
			var code = $box.find( '.upw-2fa-current' ).val();
			fw.confirm( t.confirmOff, function () {
				post( 'disable', { code: code } ).then( function () {
					window.location.reload();
				}, function ( m ) {
					say( m, true );
				} );
			} );
		} );

		$box.on( 'click', '.upw-2fa-reset', function () {
			fw.confirm( $( this ).data( 'confirm' ), function () {
				post( 'reset' ).then( function () {
					window.location.reload();
				}, function ( m ) {
					say( m, true );
				} );
			} );
		} );

		$box.on( 'click', '.upw-2fa-copy', function () {
			var text = $box.find( '.upw-2fa-code-list' ).text();
			if ( navigator.clipboard ) {
				navigator.clipboard.writeText( text ).then( function () {
					say( t.copied );
				} );
			}
		} );

		$box.on( 'click', '.upw-2fa-done', function () {
			window.location.reload();
		} );
	} );
}( jQuery ) );

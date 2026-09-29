/* Security settings page: native nav-tabs over one form, and confirmation
 * dialogs for the destructive tools. */
( function ( $ ) {
	'use strict';

	$( function () {
		var $wrap = $( '.fw-ext-security' );
		if ( ! $wrap.length ) {
			return;
		}

		function activate( tab ) {
			if ( ! $wrap.find( '#panel-' + tab ).length ) {
				tab = 'status';
			}
			$wrap.find( '.upw-sec-tabs .nav-tab' ).each( function () {
				$( this ).toggleClass( 'nav-tab-active', $( this ).data( 'tab' ) === tab );
			} );
			$wrap.find( '.upw-sec-panel' ).removeClass( 'is-active' );
			$wrap.find( '#panel-' + tab ).addClass( 'is-active' );
			$wrap.find( 'input[name="upw_tab"]' ).val( 'status' === tab ? '' : tab );
		}

		$wrap.on( 'click', '.upw-sec-tabs .nav-tab', function ( e ) {
			e.preventDefault();
			var tab = $( this ).data( 'tab' );
			activate( tab );
			if ( window.history && window.history.replaceState ) {
				window.history.replaceState( null, '', '#' + tab );
			}
		} );

		activate( ( window.location.hash || '#status' ).slice( 1 ) );

		// Back / forward, and links to another tab on this page.
		$( window ).on( 'hashchange', function () {
			activate( ( window.location.hash || '#status' ).slice( 1 ) );
		} );

		$wrap.on( 'click', '.upw-sec-confirm', function ( e ) {
			e.preventDefault();
			var href = this.href;
			fw.confirm( $( this ).data( 'confirm' ), function () {
				window.location.href = href;
			} );
		} );
	} );
}( jQuery ) );

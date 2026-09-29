<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * XML-RPC control.
 *
 *   pingbacks — removes the pingback methods, the X-Pingback header and the
 *               pingback <link>, so the site cannot be used as a reflector in
 *               pingback floods or as a relay for requests to other hosts.
 *   block     — refuses every XML-RPC request with a 403 before the server
 *               class loads.
 *
 * Not a brute-force fix: core stopped multicall password amplification long
 * ago, and login throttling covers XML-RPC logins.
 *
 * Note: the core `xmlrpc_enabled` filter only disables methods that need a
 * login. Pingbacks keep answering with it set, which is why this does not
 * rely on it.
 */
class FW_Security_Xmlrpc {

	/**
	 * @param string $mode 'leave' | 'pingbacks' | 'block'
	 */
	public static function init( $mode ) {
		if ( 'block' === $mode ) {
			if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
				self::refuse();
			}
			add_filter( 'xmlrpc_enabled', '__return_false' );
			remove_action( 'wp_head', 'rsd_link' );
			self::drop_pingbacks();

			return;
		}
		if ( 'pingbacks' === $mode ) {
			self::drop_pingbacks();
		}
	}

	private static function drop_pingbacks() {
		add_filter( 'xmlrpc_methods', [ __CLASS__, '_remove_pingback_methods' ] );
		add_filter( 'wp_headers', [ __CLASS__, '_remove_pingback_header' ] );
		add_filter( 'bloginfo_url', [ __CLASS__, '_blank_pingback_url' ], 10, 2 );
		add_filter( 'pings_open', '__return_false' );
	}

	/**
	 * @param array $methods
	 * @return array
	 */
	public static function _remove_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );

		return $methods;
	}

	/**
	 * @param array $headers
	 * @return array
	 */
	public static function _remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );

		return $headers;
	}

	/**
	 * Themes print `<link rel="pingback" href="<?php bloginfo('pingback_url') ?>">`;
	 * an empty URL is the only theme-independent way to stop advertising it.
	 *
	 * @param string $output
	 * @param string $show
	 * @return string
	 */
	public static function _blank_pingback_url( $output, $show ) {
		return 'pingback_url' === $show ? '' : $output;
	}

	private static function refuse() {
		status_header( 403 );
		header( 'Content-Type: text/xml; charset=UTF-8' );
		echo '<?xml version="1.0"?><methodResponse><fault><value><struct>'
			. '<member><name>faultCode</name><value><int>403</int></value></member>'
			. '<member><name>faultString</name><value><string>XML-RPC services are disabled on this site.</string></value></member>'
			. '</struct></value></fault></methodResponse>';
		exit;
	}
}

/**
 * Front-end security headers.
 *
 * Core already sends frame and referrer headers on wp-login.php and wp-admin;
 * the front end gets none. Each header here is its own switch.
 *
 * Headers sent from PHP never reach static files or page-cached HTML — the
 * server or a CDN is the better place for them, and the Site Health check
 * reports what visitors actually receive.
 */
class FW_Security_Headers {

	const HSTS_WINDDOWN_OPTION = 'upw_security_hsts_winddown';

	/** @var array */
	private static $s = [];

	/**
	 * @param array $settings
	 * @param bool  $safe_mode
	 */
	public static function init( array $settings, $safe_mode ) {
		self::$s = $safe_mode ? [] : $settings;
		add_action( 'send_headers', [ __CLASS__, '_send' ] );
	}

	public static function _send() {
		if ( is_admin() || headers_sent() ) {
			return;
		}

		$s = self::$s;

		if ( ! empty( $s['hdr_frame'] ) ) {
			header( 'X-Frame-Options: SAMEORIGIN' );
			// Appended, not replaced, so another component's CSP survives.
			header( "Content-Security-Policy: frame-ancestors 'self'", false );
		}
		if ( ! empty( $s['hdr_nosniff'] ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}
		$referrer = (string) ( $s['hdr_referrer'] ?? 'off' );
		if ( 'off' !== $referrer && in_array( $referrer, self::referrer_policies(), true ) ) {
			header( 'Referrer-Policy: ' . $referrer );
		}

		if ( ! is_ssl() ) {
			return; // browsers ignore HSTS over plain HTTP anyway
		}
		if ( ! empty( $s['hdr_hsts'] ) ) {
			$value = 'max-age=' . self::hsts_max_age( $s );
			if ( ! empty( $s['hsts_subdomains'] ) ) {
				$value .= '; includeSubDomains';
			}
			header( 'Strict-Transport-Security: ' . $value );
		} elseif ( (int) get_option( self::HSTS_WINDDOWN_OPTION, 0 ) > time() ) {
			// HSTS was switched off: returning browsers still remember it, so
			// tell them to forget it for as long as the old max-age could last.
			// This runs in safe mode too — it only undoes.
			header( 'Strict-Transport-Security: max-age=0' );
		}
	}

	/**
	 * @param array $s
	 * @return int
	 */
	public static function hsts_max_age( array $s ) {
		$age = (int) ( $s['hsts_max_age'] ?? DAY_IN_SECONDS );

		return in_array( $age, array_keys( self::hsts_choices() ), true ) ? $age : DAY_IN_SECONDS;
	}

	/**
	 * @return array<int, string>
	 */
	public static function hsts_choices() {
		return [
			DAY_IN_SECONDS       => __( '1 day (start here)', 'fw' ),
			WEEK_IN_SECONDS      => __( '1 week', 'fw' ),
			30 * DAY_IN_SECONDS  => __( '30 days', 'fw' ),
			180 * DAY_IN_SECONDS => __( '6 months', 'fw' ),
			YEAR_IN_SECONDS      => __( '1 year', 'fw' ),
		];
	}

	/**
	 * @return string[]
	 */
	public static function referrer_policies() {
		return [ 'strict-origin-when-cross-origin', 'same-origin', 'strict-origin', 'no-referrer' ];
	}
}

/**
 * Limits on anonymous user listing — noise reduction, not protection.
 *
 * Usernames are not secrets (bylines, author archive URLs and the lost-password
 * form reveal them). This only stops automated tools harvesting them in bulk.
 * Logged-in users are unaffected, so the block editor's author list works.
 */
class FW_Security_User_Listing {

	public static function init() {
		add_filter( 'redirect_canonical', [ __CLASS__, '_stop_author_redirect' ], 10, 2 );
		add_filter( 'rest_pre_dispatch', [ __CLASS__, '_guard_users_route' ], 10, 3 );
		add_filter( 'oembed_response_data', [ __CLASS__, '_strip_oembed_author' ] );
	}

	/**
	 * `?author=N` redirects to the author's slug; for visitors, answer 404 instead.
	 *
	 * @param string|false $redirect
	 * @param string       $requested
	 * @return string|false
	 */
	public static function _stop_author_redirect( $redirect, $requested ) {
		if ( is_user_logged_in() || ! isset( $_GET['author'] ) ) {
			return $redirect;
		}
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();

		return false;
	}

	/**
	 * @param mixed           $result
	 * @param WP_REST_Server  $server
	 * @param WP_REST_Request $request
	 * @return mixed
	 */
	public static function _guard_users_route( $result, $server, $request ) {
		if ( null !== $result || is_user_logged_in() ) {
			return $result;
		}
		if ( 0 !== strpos( $request->get_route(), '/wp/v2/users' ) ) {
			return $result;
		}

		return new WP_Error(
			'rest_user_cannot_view',
			__( 'Sorry, you are not allowed to list users.', 'fw' ),
			[ 'status' => rest_authorization_required_code() ]
		);
	}

	/**
	 * @param array $data
	 * @return array
	 */
	public static function _strip_oembed_author( $data ) {
		unset( $data['author_name'], $data['author_url'] );

		return $data;
	}
}

/**
 * Emergency session reset: destroys every user's session tokens, which
 * invalidates every login cookie at once. Everyone — including whoever runs
 * it — signs in again. Passwords and application passwords are untouched.
 */
class FW_Security_Sessions {

	/**
	 * @return int number of users whose sessions were destroyed
	 */
	public static function logout_all() {
		global $wpdb;
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'" );
		WP_Session_Tokens::destroy_all_for_all_users();

		return $count;
	}
}

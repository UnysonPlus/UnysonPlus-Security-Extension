<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * A custom login address.
 *
 * What it buys: fewer automated requests against wp-login.php — less log
 * noise, less PHP work. What it does not: protection. The REST API, admin-ajax
 * and XML-RPC stay reachable, and any login link printed on the site reveals
 * the address. Throttling and two-factor sign-in are the protection.
 *
 * Stateless by design. No rewrite rules and no files: each request compares
 * its path with the slug and, on a match, runs wp-login.php in place. Nothing
 * outlives the extension, so deactivating it, deactivating the plugin,
 * deleting it, or a fatal error all leave stock wp-login.php working at once.
 */
class FW_Security_Login_Url {

	/** @var string */
	private static $slug = '';

	/** @var bool wp-login.php is running because the custom address was requested. */
	private static $serving = false;

	/**
	 * @param string $slug
	 */
	public static function init( $slug ) {
		if ( '' === $slug || is_multisite() || '' === (string) get_option( 'permalink_structure' ) ) {
			return;
		}
		self::$slug = $slug;

		add_filter( 'site_url', [ __CLASS__, '_filter_url' ], 100, 1 );
		add_filter( 'network_site_url', [ __CLASS__, '_filter_url' ], 100, 1 );
		add_filter( 'wp_redirect', [ __CLASS__, '_filter_url' ], 100, 1 );
		add_filter( 'lostpassword_redirect', [ __CLASS__, '_filter_url' ], 100, 1 );
		add_filter( 'registration_redirect', [ __CLASS__, '_filter_url' ], 100, 1 );

		// wp_loaded: after plugins and the theme are ready (so a 404 can use the
		// theme's template), before WordPress routes the request.
		add_action( 'wp_loaded', [ __CLASS__, '_route' ], 1 );
	}

	/**
	 * @return string
	 */
	public static function url() {
		return home_url( '/' . self::$slug );
	}

	/**
	 * The standard wp-login.php address, built without going through the
	 * site_url filter this class adds — which, in the same request that
	 * resets the slug, would still point at the old one.
	 *
	 * @return string
	 */
	public static function stock_url() {
		return rtrim( (string) get_option( 'siteurl' ), '/' ) . '/wp-login.php';
	}

	public static function _route() {
		if ( self::$serving ) {
			return;
		}
		global $pagenow;

		if ( self::is_slug_request() ) {
			self::serve();
		}

		if ( 'wp-login.php' === $pagenow ) {
			// Password-protected post forms on cached pages may still post here;
			// that is not a login and must keep working.
			if ( isset( $_GET['action'] ) && 'postpass' === $_GET['action'] ) {
				return;
			}
			self::not_found();
		}

		// A logged-out visit to wp-admin would normally redirect to the login
		// address, which would reveal it. admin-ajax and admin-post stay open.
		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax()
			&& ! in_array( $pagenow, [ 'admin-post.php', 'admin-ajax.php' ], true )
			&& ! ( defined( 'WP_CLI' ) && WP_CLI ) && ! wp_doing_cron() ) {
			self::not_found();
		}
	}

	/**
	 * @return bool
	 */
	private static function is_slug_request() {
		$path = wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '', PHP_URL_PATH );
		$path = rtrim( rawurldecode( (string) $path ), '/' );
		$home = rtrim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );

		return $path === $home . '/' . self::$slug;
	}

	/**
	 * Run wp-login.php for this request.
	 */
	private static function serve() {
		// wp-login.php's own functions read these as globals; declared here so
		// its top-level code (now running inside this method) writes the real ones.
		global $error, $interim_login, $action, $user_login, $pagenow;

		self::$serving = true;
		$pagenow       = 'wp-login.php';
		$home          = rtrim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		// core's is_login() compares SCRIPT_NAME with wp_login_url().
		$_SERVER['SCRIPT_NAME'] = $home . '/' . self::$slug;

		nocache_headers();
		require ABSPATH . 'wp-login.php';
		exit;
	}

	private static function not_found() {
		global $wp_query;
		nocache_headers();
		status_header( 404 );
		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		$template = get_404_template();
		if ( $template && ! is_admin() ) {
			include $template;
		} else {
			echo '<!doctype html><title>' . esc_html__( 'Page not found', 'fw' ) . '</title><h1>' . esc_html__( 'Page not found', 'fw' ) . '</h1>';
		}
		exit;
	}

	/**
	 * Point every URL that names wp-login.php at the custom address, keeping
	 * its query string. Handles absolute and relative forms.
	 *
	 * @param string $url
	 * @return string
	 */
	public static function _filter_url( $url ) {
		if ( ! is_string( $url ) || false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		$parts = wp_parse_url( $url );
		$path  = $parts['path'] ?? '';
		if ( 'wp-login.php' !== basename( $path ) ) {
			return $url;
		}
		// postpass is not a login; leave it pointing at wp-login.php.
		if ( ! empty( $parts['query'] ) && preg_match( '/(^|&)action=postpass(&|$)/', $parts['query'] ) ) {
			return $url;
		}

		$new = self::url();
		if ( isset( $parts['scheme'] ) && 'https' === $parts['scheme'] ) {
			$new = set_url_scheme( $new, 'https' );
		}
		if ( ! empty( $parts['query'] ) ) {
			$new .= '?' . $parts['query'];
		}
		if ( ! empty( $parts['fragment'] ) ) {
			$new .= '#' . $parts['fragment'];
		}

		return $new;
	}

	/**
	 * Fetch the custom address the way a visitor would, and confirm it shows
	 * the login form. Used right after saving a slug: if it does not, the save
	 * is reverted rather than leaving the owner without a way in.
	 *
	 * @param string $slug
	 * @return true|WP_Error WP_Error code 'unreachable' = could not check (loopback blocked)
	 */
	public static function probe( $slug ) {
		$response = wp_remote_get( add_query_arg( 'upw_probe', wp_generate_password( 8, false ), home_url( '/' . $slug ) ), [
			'timeout'     => 10,
			'redirection' => 0,
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			'headers'     => [ 'Cache-Control' => 'no-cache' ],
		] );
		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'unreachable', $response->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$body = (string) wp_remote_retrieve_body( $response );
		if ( 200 !== $code || false === strpos( $body, 'id="loginform"' ) ) {
			/* translators: %d: HTTP status code */
			return new WP_Error( 'not_login', sprintf( __( 'The new address answered with HTTP %d instead of the login form.', 'fw' ), $code ) );
		}

		return true;
	}
}

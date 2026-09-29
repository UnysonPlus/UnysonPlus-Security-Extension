<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Security checks added to Tools → Site Health.
 *
 * Only what core does not already test: core covers versions, HTTPS, debug
 * mode, the default registration role and auto-updates. Everything here is
 * read-only. A check that cannot run (a blocked loopback request) reports
 * "could not check" — never a pass.
 */
class FW_Security_Site_Health {

	/** @var FW_Extension_Security */
	private static $ext;

	/**
	 * @param FW_Extension_Security $ext
	 */
	public static function init( $ext ) {
		self::$ext = $ext;
		add_filter( 'site_status_tests', [ __CLASS__, '_register' ] );

		// The Site Health screen runs a has_rest:false async test by posting to
		// admin-ajax.php as "health-check-<test>"; async_direct_test is only
		// used by the background (cron) run.
		foreach ( [ 'debug_log', 'dir_list', 'headers' ] as $id ) {
			add_action( 'wp_ajax_health-check-upw_security_' . $id, static function () use ( $id ) {
				check_ajax_referer( 'health-check-site-status' );
				if ( ! current_user_can( 'view_site_health_checks' ) ) {
					wp_send_json_error();
				}
				wp_send_json_success( call_user_func( [ __CLASS__, 'test_' . $id ] ) );
			} );
		}
	}

	/**
	 * @param array $tests
	 * @return array
	 */
	public static function _register( $tests ) {
		$direct = [
			'file_edit'   => __( 'File editor', 'fw' ),
			'salts'       => __( 'Security keys and salts', 'fw' ),
			'xmlrpc'      => __( 'XML-RPC', 'fw' ),
			'app_pw'      => __( 'Application passwords', 'fw' ),
			'proxy'       => __( 'Visitor addresses', 'fw' ),
			'safe_mode'   => __( 'Security safe mode', 'fw' ),
			'two_factor'  => __( 'Two-factor sign-in for administrators', 'fw' ),
			'login_slug'  => __( 'Custom login address', 'fw' ),
			'svg_uploads' => __( 'SVG uploads', 'fw' ),
		];
		foreach ( $direct as $id => $label ) {
			$tests['direct'][ 'upw_security_' . $id ] = [
				'label' => $label,
				'test'  => [ __CLASS__, 'test_' . $id ],
			];
		}

		$async = [
			'debug_log' => __( 'Public debug log', 'fw' ),
			'dir_list'  => __( 'Uploads directory listing', 'fw' ),
			'headers'   => __( 'Security headers', 'fw' ),
		];
		foreach ( $async as $id => $label ) {
			$tests['async'][ 'upw_security_' . $id ] = [
				'label'             => $label,
				'test'              => 'upw_security_' . $id,
				'has_rest'          => false,
				'async_direct_test' => [ __CLASS__, 'test_' . $id ],
			];
		}

		return $tests;
	}

	/* ---------------------------------------------------------------------
	 * Result builder
	 * ------------------------------------------------------------------ */

	/**
	 * @param string $id
	 * @param string $status 'good' | 'recommended' | 'critical'
	 * @param string $label
	 * @param string $description HTML
	 * @param string $actions     HTML
	 * @return array
	 */
	private static function result( $id, $status, $label, $description, $actions = '' ) {
		return [
			'label'       => $label,
			'status'      => $status,
			'badge'       => [ 'label' => __( 'Security', 'fw' ), 'color' => 'good' === $status ? 'blue' : ( 'critical' === $status ? 'red' : 'orange' ) ],
			'description' => $description,
			'actions'     => $actions,
			'test'        => 'upw_security_' . $id,
		];
	}

	/**
	 * @param string $code
	 * @return string
	 */
	private static function code( $code ) {
		return '<p><code>' . esc_html( $code ) . '</code></p>';
	}

	/**
	 * @return string
	 */
	private static function settings_link() {
		return sprintf( '<p><a href="%s">%s</a></p>', esc_url( FW_Extension_Security::page_url() ), esc_html__( 'Security settings', 'fw' ) );
	}

	/* ---------------------------------------------------------------------
	 * Direct tests
	 * ------------------------------------------------------------------ */

	public static function test_file_edit() {
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			return self::result( 'file_edit', 'good', __( 'Code cannot be changed from the dashboard', 'fw' ),
				'<p>' . esc_html__( 'DISALLOW_FILE_MODS is set: the file editor and plugin/theme installs are off, so a stolen administrator login cannot add code through the dashboard. Updates are applied some other way.', 'fw' ) . '</p>' );
		}
		if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) {
			return self::result( 'file_edit', 'good', __( 'The dashboard file editor is off', 'fw' ),
				'<p>' . esc_html__( 'DISALLOW_FILE_EDIT is set. Note what it does not do: an administrator can still upload a plugin, which runs code. Only DISALLOW_FILE_MODS closes that, at the cost of installing and updating from the dashboard.', 'fw' ) . '</p>' );
		}

		return self::result( 'file_edit', 'recommended', __( 'The dashboard file editor is on', 'fw' ),
			'<p>' . esc_html__( 'Anyone with an administrator login can edit plugin and theme code from the dashboard. Turning the editor off stops accidental edits and one common way an attack chain turns into code on the server. It does not stop a determined administrator-level attacker, who can still upload a plugin. Add this line to wp-config.php:', 'fw' ) . '</p>'
			. self::code( "define( 'DISALLOW_FILE_EDIT', true );" ) );
	}

	public static function test_salts() {
		$bad = [];
		foreach ( [ 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ] as $c ) {
			if ( ! defined( $c ) || strlen( (string) constant( $c ) ) < 32 || false !== stripos( (string) constant( $c ), 'put your unique phrase here' ) ) {
				$bad[] = $c;
			}
		}
		if ( ! $bad ) {
			return self::result( 'salts', 'good', __( 'Security keys and salts are set', 'fw' ),
				'<p>' . esc_html__( 'All eight keys in wp-config.php are set and not the placeholder text. Replacing them logs every user out — a useful step after a suspected break-in.', 'fw' ) . '</p>' );
		}

		return self::result( 'salts', 'critical', __( 'Security keys or salts are missing or weak', 'fw' ),
			'<p>' . esc_html( sprintf(
				/* translators: %s: list of constant names */
				__( 'These are missing, short or still the placeholder: %s. They sign login cookies; weak values make cookies easier to forge. Generate a fresh set and replace the block in wp-config.php (everyone will need to sign in again).', 'fw' ),
				implode( ', ', $bad )
			) ) . '</p>'
			. '<p><a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Generate a new set', 'fw' ) . '</a></p>' );
	}

	public static function test_xmlrpc() {
		$mode = self::$ext->active_setting( 'xmlrpc_mode', 'leave' );
		if ( 'block' === $mode ) {
			return self::result( 'xmlrpc', 'good', __( 'XML-RPC is blocked', 'fw' ), '<p>' . esc_html__( 'Every XML-RPC request is refused.', 'fw' ) . '</p>' );
		}
		if ( 'pingbacks' === $mode ) {
			return self::result( 'xmlrpc', 'good', __( 'XML-RPC pingbacks are off', 'fw' ), '<p>' . esc_html__( 'Pingback methods are removed; other XML-RPC methods still answer.', 'fw' ) . '</p>' );
		}

		return self::result( 'xmlrpc', 'recommended', __( 'XML-RPC pingbacks are on', 'fw' ),
			'<p>' . esc_html__( 'Pingbacks let anyone make your site send a request to another address, which is used in reflection floods. If nothing you use publishes through XML-RPC, turn pingbacks off or block XML-RPC. (The Theme Settings “Disable XML-RPC logins” switch only turns off methods that need a login; pingbacks keep answering.)', 'fw' ) . '</p>',
			self::settings_link() );
	}

	public static function test_app_pw() {
		if ( ! wp_is_application_passwords_available() ) {
			return self::result( 'app_pw', 'good', __( 'Application passwords are unavailable', 'fw' ), '<p>' . esc_html__( 'WordPress offers them only over HTTPS or on local sites.', 'fw' ) . '</p>' );
		}
		global $wpdb;
		$users = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value NOT IN ('', 'a:0:{}')", '_application_passwords' ) );

		return self::result( 'app_pw', 'good',
			/* translators: %d: number of users */
			sprintf( _n( '%d user has application passwords', '%d users have application passwords', $users, 'fw' ), $users ),
			'<p>' . esc_html__( 'Application passwords let programs sign in to the REST API and XML-RPC. Each can be revoked on its own from the user’s profile. They are not asked for a two-factor code, by design — review and revoke any you no longer recognise.', 'fw' ) . '</p>' );
	}

	public static function test_proxy() {
		if ( FW_Security_IP::proxy_suspected() ) {
			return self::result( 'proxy', 'critical', __( 'Visitors may all appear to come from one address', 'fw' ),
				'<p>' . esc_html__( 'This request came from a private address carrying a forwarding header, so the site is behind a proxy or CDN. Unless the forwarding header is configured, per-visitor limits (login throttling and the framework’s rate limits) would treat every visitor as the same one. Login throttling refuses to switch on until this is set.', 'fw' ) . '</p>',
				self::settings_link() );
		}

		return self::result( 'proxy', 'good', __( 'Visitor addresses look reliable', 'fw' ),
			'<p>' . esc_html__( 'No unconfigured proxy was detected on this request.', 'fw' ) . '</p>' );
	}

	public static function test_safe_mode() {
		if ( FW_Extension_Security::is_safe_mode() ) {
			return self::result( 'safe_mode', 'critical', __( 'Security safe mode is on', 'fw' ),
				'<p>' . esc_html__( 'UPW_SECURITY_SAFE_MODE is set in wp-config.php, so every Security measure that changes behaviour is off. Remove the line once you have regained access.', 'fw' ) . '</p>' );
		}

		return self::result( 'safe_mode', 'good', __( 'Security safe mode is off', 'fw' ), '<p>' . esc_html__( 'Measures you switched on are running.', 'fw' ) . '</p>' );
	}

	public static function test_two_factor() {
		$admins  = get_users( [ 'role' => 'administrator', 'fields' => 'ID' ] );
		$without = array_filter( $admins, static fn( $id ) => ! FW_Security_Two_Factor::is_enrolled( (int) $id ) );

		if ( ! self::$ext->active_setting( 'twofa_enabled', false ) ) {
			return self::result( 'two_factor', 'recommended', __( 'Two-factor sign-in is not available', 'fw' ),
				'<p>' . esc_html__( 'A second factor defeats leaked, reused and guessed passwords — the most effective account protection available. Switch it on in Security, then each administrator sets it up on their profile.', 'fw' ) . '</p>',
				self::settings_link() );
		}
		if ( $without ) {
			return self::result( 'two_factor', 'recommended',
				/* translators: %d: number of administrators */
				sprintf( _n( '%d administrator has not set up two-factor sign-in', '%d administrators have not set up two-factor sign-in', count( $without ), 'fw' ), count( $without ) ),
				'<p>' . esc_html__( 'Each administrator sets it up from their own profile (Users → Profile).', 'fw' ) . '</p>' );
		}

		return self::result( 'two_factor', 'good', __( 'Every administrator uses two-factor sign-in', 'fw' ), '' );
	}

	public static function test_login_slug() {
		$slug = self::$ext->login_slug();
		if ( '' === $slug ) {
			return self::result( 'login_slug', 'good', __( 'The login page is at its standard address', 'fw' ), '<p>' . esc_html__( 'No custom login address is set.', 'fw' ) . '</p>' );
		}
		$content = FW_Security_Slug_Rules::resolves( $slug );
		global $wpdb;
		$post = $wpdb->get_var( $wpdb->prepare( "SELECT post_title FROM {$wpdb->posts} WHERE post_name = %s AND post_status NOT IN ('auto-draft','trash') LIMIT 1", $slug ) );
		if ( $post || '' !== $content ) {
			return self::result( 'login_slug', 'critical', __( 'Content now uses the custom login address', 'fw' ),
				'<p>' . esc_html( sprintf(
					/* translators: %s: the login address */
					__( 'Something on the site now has the address %s. The login page still wins, so that content cannot be reached. Rename the content or choose a new login address.', 'fw' ),
					home_url( '/' . $slug )
				) ) . '</p>', self::settings_link() );
		}

		return self::result( 'login_slug', 'good', __( 'The custom login address is clear', 'fw' ),
			'<p>' . esc_html__( 'Nothing else on the site uses it. Remember it is obscurity, not protection: any login link on the site reveals it.', 'fw' ) . '</p>' );
	}

	public static function test_svg_uploads() {
		if ( ! function_exists( 'sc_svg_upload_roles' ) ) {
			return self::result( 'svg_uploads', 'good', __( 'SVG uploads are not enabled by UnysonPlus', 'fw' ), '' );
		}
		$roles = sc_svg_upload_roles();
		$wider = array_diff( $roles, [ 'administrator' ] );

		if ( $wider ) {
			return self::result( 'svg_uploads', 'recommended', __( 'Roles other than administrators can upload SVG files', 'fw' ),
				'<p>' . esc_html( sprintf(
					/* translators: %s: role names */
					__( 'Allowed: %s. Uploaded SVGs are sanitised, but every extra role is extra trust in that sanitiser. Keep SVG uploads to roles that need them (Page Builder settings).', 'fw' ),
					implode( ', ', $roles )
				) ) . '</p>' );
		}

		return self::result( 'svg_uploads', 'good', __( 'Only administrators can upload SVG files', 'fw' ),
			'<p>' . esc_html__( 'SVG uploads are limited to administrators and sanitised on upload.', 'fw' ) . '</p>' );
	}

	/* ---------------------------------------------------------------------
	 * Async (loopback) tests
	 * ------------------------------------------------------------------ */

	/**
	 * @param string $url
	 * @param string $method
	 * @return array|WP_Error
	 */
	private static function fetch( $url, $method = 'GET' ) {
		return wp_remote_request( $url, [
			'method'      => $method,
			'timeout'     => 10,
			'redirection' => 0,
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			'headers'     => [ 'Cache-Control' => 'no-cache' ],
		] );
	}

	/**
	 * @param string   $id
	 * @param string   $label
	 * @param WP_Error $error
	 * @return array
	 */
	private static function could_not_check( $id, $label, $error ) {
		return self::result( $id, 'recommended', $label,
			'<p>' . esc_html( sprintf(
				/* translators: %s: error message */
				__( 'Could not check: the site could not request its own pages (%s). This is not a pass.', 'fw' ),
				$error->get_error_message()
			) ) . '</p>' );
	}

	public static function test_debug_log() {
		$path = ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) ) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
		$root = wp_normalize_path( ABSPATH );
		$norm = wp_normalize_path( $path );

		if ( ! file_exists( $path ) ) {
			return self::result( 'debug_log', 'good', __( 'No debug log file found', 'fw' ), '' );
		}
		if ( 0 !== strpos( $norm, $root ) ) {
			return self::result( 'debug_log', 'good', __( 'The debug log is outside the web root', 'fw' ), '' );
		}

		$url      = site_url( '/' . ltrim( substr( $norm, strlen( $root ) ), '/' ) );
		$response = self::fetch( $url, 'HEAD' );
		if ( is_wp_error( $response ) ) {
			return self::could_not_check( 'debug_log', __( 'Public debug log', 'fw' ), $response );
		}
		if ( 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			return self::result( 'debug_log', 'critical', __( 'The debug log can be downloaded by anyone', 'fw' ),
				'<p>' . esc_html( sprintf(
					/* translators: %s: URL */
					__( '%s is publicly readable. Debug logs reveal file paths and sometimes data. Move it outside the web root (set WP_DEBUG_LOG to a path), delete it, or deny it at the web server.', 'fw' ),
					$url
				) ) . '</p>' );
		}

		return self::result( 'debug_log', 'good', __( 'The debug log is not publicly readable', 'fw' ), '' );
	}

	public static function test_dir_list() {
		$uploads  = wp_get_upload_dir();
		$response = self::fetch( trailingslashit( $uploads['baseurl'] ) );
		if ( is_wp_error( $response ) ) {
			return self::could_not_check( 'dir_list', __( 'Uploads directory listing', 'fw' ), $response );
		}
		$body = (string) wp_remote_retrieve_body( $response );
		if ( 200 === (int) wp_remote_retrieve_response_code( $response ) && preg_match( '/<title>\s*Index of|Directory listing for/i', $body ) ) {
			return self::result( 'dir_list', 'recommended', __( 'The uploads folder lists its files', 'fw' ),
				'<p>' . esc_html__( 'Anyone can browse every uploaded file, including ones never linked from a page. Turn directory listing off at the web server (for example “Options -Indexes” on Apache).', 'fw' ) . '</p>' );
		}

		return self::result( 'dir_list', 'good', __( 'The uploads folder does not list its files', 'fw' ), '' );
	}

	public static function test_headers() {
		$response = self::fetch( home_url( '/' ) );
		if ( is_wp_error( $response ) ) {
			return self::could_not_check( 'headers', __( 'Security headers', 'fw' ), $response );
		}
		$want = [
			'x-frame-options'           => __( 'framing protection', 'fw' ),
			'x-content-type-options'    => __( 'MIME-sniffing protection', 'fw' ),
			'referrer-policy'           => __( 'a referrer policy', 'fw' ),
			'strict-transport-security' => 'HSTS',
		];
		$present = [];
		$missing = [];
		$dupes   = [];
		foreach ( $want as $h => $label ) {
			$value = wp_remote_retrieve_header( $response, $h );
			if ( '' === $value || [] === $value ) {
				$missing[] = $label;
				continue;
			}
			$present[] = $label;
			if ( is_array( $value ) && count( $value ) > 1 ) {
				$dupes[] = $h;
			}
		}
		if ( ! is_ssl() && ! wp_is_using_https() ) {
			$missing = array_diff( $missing, [ 'HSTS' ] );
		}

		$desc = '<p>' . esc_html( sprintf(
			/* translators: 1: list, 2: list */
			__( 'The home page currently sends: %1$s. Missing: %2$s.', 'fw' ),
			$present ? implode( ', ', $present ) : __( 'none', 'fw' ),
			$missing ? implode( ', ', $missing ) : __( 'none', 'fw' )
		) ) . '</p>';
		if ( $dupes ) {
			$desc .= '<p>' . esc_html( sprintf(
				/* translators: %s: header names */
				__( 'Sent twice (the server and WordPress both add it): %s. Switch it off on one side.', 'fw' ),
				implode( ', ', $dupes )
			) ) . '</p>';
		}
		$desc .= '<p>' . esc_html__( 'Headers set by WordPress do not reach static files or page-cached pages; the web server or CDN is the most reliable place for them.', 'fw' ) . '</p>';

		return self::result( 'headers', $missing ? 'recommended' : 'good',
			$missing ? __( 'Some security headers are missing', 'fw' ) : __( 'Security headers are present', 'fw' ),
			$desc, $missing ? self::settings_link() : '' );
	}

	/**
	 * On-demand only (a button on the Status tab): writes a harmless PHP file
	 * into uploads, requests it and deletes it.
	 *
	 * @return array{status: string, message: string}
	 */
	public static function probe_php_in_uploads() {
		$uploads = wp_get_upload_dir();
		$name    = 'upw-sec-probe-' . wp_generate_password( 12, false ) . '.php';
		$token   = wp_generate_password( 24, false );
		$file    = trailingslashit( $uploads['basedir'] ) . $name;

		if ( false === @file_put_contents( $file, '<?php echo "' . $token . '";' ) ) {
			return [ 'status' => 'unknown', 'message' => __( 'Could not write a test file into uploads.', 'fw' ) ];
		}
		$response = self::fetch( trailingslashit( $uploads['baseurl'] ) . $name );
		@unlink( $file );

		if ( is_wp_error( $response ) ) {
			return [ 'status' => 'unknown', 'message' => sprintf( __( 'Could not check: %s', 'fw' ), $response->get_error_message() ) ];
		}
		if ( false !== strpos( (string) wp_remote_retrieve_body( $response ), $token ) ) {
			$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? (string) $_SERVER['SERVER_SOFTWARE'] : '';

			return [
				'status'  => 'bad',
				'message' => ( false !== stripos( $server, 'nginx' ) )
					? __( 'PHP runs inside uploads. On this server, add a location rule that denies .php under the uploads path.', 'fw' )
					: __( 'PHP runs inside uploads. If an upload check is ever bypassed, a PHP file there becomes code on your server. On Apache, an .htaccess in the uploads folder with “<Files *.php> Require all denied </Files>” stops it.', 'fw' ),
			];
		}

		return [ 'status' => 'good', 'message' => __( 'PHP does not run inside uploads.', 'fw' ) ];
	}
}

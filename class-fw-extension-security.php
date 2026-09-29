<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

// lib/, not includes/: the extension loader plain-includes every file in an
// active extension's includes/ folder, which redeclares these classes after
// the require_once below (a fatal on activation). Loading them explicitly also
// keeps the order deterministic and the WP-CLI file out of web requests.
require_once __DIR__ . '/lib/class-fw-security-ip.php';
require_once __DIR__ . '/lib/class-fw-security-throttle.php';
require_once __DIR__ . '/lib/class-fw-security-totp.php';
require_once __DIR__ . '/lib/class-fw-security-two-factor.php';
require_once __DIR__ . '/lib/class-fw-security-hardening.php';
require_once __DIR__ . '/lib/class-fw-security-slug-rules.php';
require_once __DIR__ . '/lib/class-fw-security-login-url.php';
require_once __DIR__ . '/lib/class-fw-security-site-health.php';

/**
 * Security.
 *
 * Every measure that changes behaviour is a module that registers its hooks
 * only when its switch is on and safe mode is off. Off means no hooks at all,
 * so an off measure is indistinguishable from stock WordPress — which is also
 * what makes each switch its own rollback. Nothing is written outside the
 * extension's settings and its own options/transients: no rewrite rules, no
 * files, no wp-config.php or .htaccess edits.
 *
 * Recovery that never needs a working admin screen:
 *   define( 'UPW_SECURITY_SAFE_MODE', true );    every measure off
 *   define( 'UPW_SECURITY_LOGIN_SLUG', false );  standard wp-login.php
 *   wp upw-security …                            status, disable, unlock, 2fa reset, login-url reset
 *   wp option patch delete fw_active_extensions security   the extension off, no code needed
 */
class FW_Extension_Security extends FW_Extension {

	const PARENT_SLUG    = 'fw-extensions';
	const PAGE_SLUG      = 'fw-security';
	const CAPABILITY     = 'manage_options';
	const SETTINGS_NONCE = 'fw_ext_security_save';
	const ACTION_NONCE   = 'fw_ext_security_action';
	const NOTICE_KEY     = 'upw_security_notice_';
	const INTRO_META     = 'upw_security_intro_dismissed';

	/** Measures, for status displays: setting key => label. */
	const MEASURES = [
		'throttle_enabled'     => 'Login throttling',
		'generic_login_errors' => 'Generic login errors',
		'twofa_enabled'        => 'Two-factor sign-in',
		'xmlrpc_mode'          => 'XML-RPC',
		'hdr_frame'            => 'Header: framing',
		'hdr_nosniff'          => 'Header: nosniff',
		'hdr_referrer'         => 'Header: referrer policy',
		'hdr_hsts'             => 'Header: HSTS',
		'limit_user_listing'   => 'User-listing limits',
		'login_slug'           => 'Custom login address',
	];

	/** @var string|null */
	private $hook_suffix = null;

	/** @var array|null */
	private $settings = null;

	/**
	 * @internal
	 */
	protected function _init() {
		$s    = $this->get_settings();
		$safe = self::is_safe_mode();

		if ( ! $safe ) {
			FW_Security_IP::configure( $s );
		}

		FW_Security_Site_Health::init( $this );
		// Always booted: the HSTS wind-down must keep running in safe mode.
		FW_Security_Headers::init( $s, $safe );

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once __DIR__ . '/lib/class-fw-security-cli.php';
			FW_Security_CLI::register();
		}

		if ( ! $safe ) {
			if ( ! empty( $s['throttle_enabled'] ) ) {
				FW_Security_Throttle::init( $s );
			}
			if ( ! empty( $s['generic_login_errors'] ) ) {
				FW_Security_Login_Errors::init();
			}
			if ( ! empty( $s['twofa_enabled'] ) ) {
				FW_Security_Two_Factor::init( ! empty( $s['throttle_enabled'] ) );
			}
			FW_Security_Xmlrpc::init( (string) $s['xmlrpc_mode'] );
			if ( ! empty( $s['limit_user_listing'] ) ) {
				FW_Security_User_Listing::init();
			}
			FW_Security_Login_Url::init( $this->login_slug() );
		}

		if ( is_admin() ) {
			add_action( 'admin_menu', [ $this, '_action_admin_menu' ], 30 );
			add_filter( 'fw_unysonplus_admin_submenu_order', [ $this, '_filter_submenu_order' ] );
			add_action( 'admin_init', [ $this, '_redirect_manager_settings_page' ] );
			add_action( 'fw_extension_settings_form_saved:' . $this->get_name(), [ $this, '_after_manager_settings_saved' ] );
			add_action( 'admin_post_upw_security_action', [ $this, '_handle_action' ] );
			add_action( 'admin_notices', [ $this, '_action_admin_notices' ] );
			add_action( 'wp_ajax_upw_security_dismiss_intro', [ $this, '_ajax_dismiss_intro' ] );
		}
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array
	 */
	public static function defaults() {
		return [
			'throttle_enabled'     => false,
			'throttle_attempts'    => '5',
			'throttle_window'      => '15',
			'throttle_lockout'     => '15',
			'throttle_lockout_max' => '12',
			'throttle_allowlist'   => '',
			'proxy_header'         => 'none',
			'proxy_header_custom'  => '',
			'proxy_trusted'        => '',
			'generic_login_errors' => false,
			'twofa_enabled'        => false,
			'xmlrpc_mode'          => 'leave',
			'hdr_frame'            => false,
			'hdr_nosniff'          => false,
			'hdr_referrer'         => 'off',
			'hdr_hsts'             => false,
			'hsts_max_age'         => (string) DAY_IN_SECONDS,
			'hsts_subdomains'      => false,
			'limit_user_listing'   => false,
			'login_slug'           => '',
		];
	}

	/**
	 * Saved settings merged over the defaults.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( null === $this->settings ) {
			// Read the stored array directly. fw_get_db_ext_settings_option()
			// loads settings-options.php to fill defaults, which initialises the
			// option types; doing that from _init() (before other extensions have
			// registered theirs) leaves e.g. the page-builder type undefined for
			// the whole request. defaults() already supplies every default.
			$saved          = get_option( 'fw_ext_settings_options:' . $this->get_name(), [] );
			$this->settings = array_merge( self::defaults(), is_array( $saved ) ? array_intersect_key( $saved, self::defaults() ) : [] );
		}

		return $this->settings;
	}

	/**
	 * @param string $key
	 * @param mixed  $default
	 * @return mixed
	 */
	public function setting( $key, $default = null ) {
		return $this->get_settings()[ $key ] ?? $default;
	}

	/**
	 * A setting as it is actually applied: the "off" value in safe mode.
	 *
	 * @param string $key
	 * @param mixed  $off
	 * @return mixed
	 */
	public function active_setting( $key, $off ) {
		return self::is_safe_mode() ? $off : $this->setting( $key, $off );
	}

	/**
	 * @param string $key a MEASURES key
	 * @return bool
	 */
	public function measure_running( $key ) {
		if ( self::is_safe_mode() ) {
			return false;
		}
		if ( 'login_slug' === $key ) {
			return '' !== $this->login_slug() && ! is_multisite() && '' !== (string) get_option( 'permalink_structure' );
		}
		$v = $this->setting( $key );

		return is_bool( $v ) ? $v : ! in_array( (string) $v, [ '', 'off', 'leave' ], true );
	}

	/**
	 * @return bool
	 */
	public static function is_safe_mode() {
		return defined( 'UPW_SECURITY_SAFE_MODE' ) && UPW_SECURITY_SAFE_MODE;
	}

	/**
	 * The effective login slug: the wp-config constant wins over the setting.
	 *
	 * @return string '' = standard wp-login.php
	 */
	public function login_slug() {
		if ( defined( 'UPW_SECURITY_LOGIN_SLUG' ) ) {
			$c = UPW_SECURITY_LOGIN_SLUG;

			return is_string( $c ) ? strtolower( trim( $c, "/ \t" ) ) : '';
		}

		return (string) $this->setting( 'login_slug', '' );
	}

	/**
	 * Merge changes into the saved settings, unvalidated. For WP-CLI, whose
	 * commands either only turn things off or validate first.
	 *
	 * @param array $changes
	 */
	public function save_settings( array $changes ) {
		$before = $this->get_settings();
		$values = array_merge( $before, array_intersect_key( $changes, self::defaults() ) );
		$this->note_hsts_winddown( $before, $values );
		fw_set_db_ext_settings_option( $this->get_name(), null, $values );
		$this->settings = null;
	}

	/**
	 * Remove every piece of data the extension stores.
	 */
	public function purge_data() {
		global $wpdb;
		fw_set_db_ext_settings_option( $this->get_name(), null, [] );
		delete_option( FW_Security_Throttle::LOCKOUTS_OPTION );
		delete_option( FW_Security_Headers::HSTS_WINDDOWN_OPTION );
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_upw\\_sec\\_%' OR option_name LIKE '\\_transient\\_timeout\\_upw\\_sec\\_%'" );
		foreach ( [ FW_Security_Two_Factor::META, FW_Security_Two_Factor::META_PENDING, FW_Security_Two_Factor::META_CODES, self::INTRO_META ] as $key ) {
			delete_metadata( 'user', 0, $key, '', true );
		}
		$this->settings = null;
	}

	/**
	 * Remember how long browsers may still hold HSTS after it is switched off.
	 *
	 * @param array $before
	 * @param array $after
	 */
	private function note_hsts_winddown( array $before, array $after ) {
		if ( ! empty( $before['hdr_hsts'] ) && empty( $after['hdr_hsts'] ) ) {
			update_option( FW_Security_Headers::HSTS_WINDDOWN_OPTION, time() + FW_Security_Headers::hsts_max_age( $before ), false );
		} elseif ( ! empty( $after['hdr_hsts'] ) ) {
			delete_option( FW_Security_Headers::HSTS_WINDDOWN_OPTION );
		}
	}

	/**
	 * Check proposed settings. Invalid fields keep their previous value; every
	 * reason is reported. Returns the values to store, errors and notes.
	 *
	 * @param array $new
	 * @param array $before
	 * @return array{0: array, 1: string[], 2: string[]}
	 */
	public function validate( array $new, array $before ) {
		$values = array_merge( $before, array_intersect_key( $new, self::defaults() ) );
		$errors = [];
		$notes  = [];

		foreach ( [ 'throttle_allowlist' => __( 'Never throttle', 'fw' ), 'proxy_trusted' => __( 'Trusted proxy addresses', 'fw' ) ] as $key => $label ) {
			$parsed = FW_Security_IP::parse_list( (string) $values[ $key ] );
			if ( $parsed['invalid'] ) {
				/* translators: 1: field label, 2: invalid entries */
				$errors[]       = sprintf( __( '%1$s: not an address or range: %2$s. That field was not changed.', 'fw' ), $label, implode( ', ', $parsed['invalid'] ) );
				$values[ $key ] = $before[ $key ];
			}
		}

		if ( 'custom' === $values['proxy_header'] && '' === FW_Security_IP::server_key( (string) $values['proxy_header_custom'] ) ) {
			$errors[]                = __( 'Enter a valid header name (letters, digits and hyphens) for “Another header”. The proxy setting was not changed.', 'fw' );
			$values['proxy_header']  = $before['proxy_header'];
			$values['proxy_header_custom'] = $before['proxy_header_custom'];
		}

		if ( ! empty( $values['throttle_enabled'] ) && 'none' === $values['proxy_header'] && FW_Security_IP::looks_proxied() ) {
			$errors[]                   = __( 'Login throttling was not switched on: this site appears to be behind a proxy or CDN, so every visitor would share one address and one attacker could lock everyone out. Set “Real visitor address comes from” first.', 'fw' );
			$values['throttle_enabled'] = ! empty( $before['throttle_enabled'] );
		}

		if ( ! empty( $values['hdr_hsts'] ) && empty( $before['hdr_hsts'] ) && ! wp_is_using_https() ) {
			$errors[]           = __( 'HSTS was not switched on: the site address does not use HTTPS.', 'fw' );
			$values['hdr_hsts'] = false;
		}

		// Login address.
		$slug = strtolower( trim( (string) $values['login_slug'], "/ \t" ) );
		if ( defined( 'UPW_SECURITY_LOGIN_SLUG' ) ) {
			$slug = (string) $before['login_slug']; // the field is disabled; keep what was saved
		} elseif ( '' !== $slug && $slug !== $before['login_slug'] ) {
			$slug_errors = FW_Security_Slug_Rules::errors( $slug );
			if ( $slug_errors ) {
				foreach ( $slug_errors as $e ) {
					/* translators: 1: slug, 2: reason */
					$errors[] = sprintf( __( 'The login address was NOT changed — “%1$s”: %2$s', 'fw' ), $slug, $e );
				}
				$slug = (string) $before['login_slug'];
			}
		}
		$values['login_slug'] = $slug;

		return [ $values, $errors, $notes ];
	}

	/**
	 * Store validated values, then prove a changed login address actually
	 * serves the login form. If it does not, put the old address back.
	 *
	 * @param array $new
	 * @return array{errors: string[], notes: string[]}
	 */
	private function save_validated( array $new ) {
		$before                     = $this->get_settings();
		[ $values, $errors, $notes ] = $this->validate( $new, $before );

		$this->note_hsts_winddown( $before, $values );
		fw_set_db_ext_settings_option( $this->get_name(), null, $values );
		$this->settings = null;

		$slug_changed = $values['login_slug'] !== $before['login_slug'] && ! defined( 'UPW_SECURITY_LOGIN_SLUG' );
		if ( $slug_changed && '' !== $values['login_slug'] && ! self::is_safe_mode() ) {
			$probe = FW_Security_Login_Url::probe( $values['login_slug'] );
			if ( is_wp_error( $probe ) && 'unreachable' !== $probe->get_error_code() ) {
				$values['login_slug'] = $before['login_slug'];
				fw_set_db_ext_settings_option( $this->get_name(), null, $values );
				$this->settings = null;
				/* translators: %s: reason */
				$errors[]     = sprintf( __( 'The login address was NOT changed: it was saved, tested, and did not show the login form, so the previous address was put back. %s', 'fw' ), $probe->get_error_message() );
				$slug_changed = false;
			} elseif ( is_wp_error( $probe ) ) {
				/* translators: %s: error */
				$notes[] = sprintf( __( 'The new login address could not be tested from the server (%s). Open it in a private window before you sign out.', 'fw' ), $probe->get_error_message() );
			}
		}

		if ( $slug_changed ) {
			$notes[] = $this->announce_login_url( $values['login_slug'] );
		}

		return [ 'errors' => $errors, 'notes' => $notes ];
	}

	/**
	 * Email the new login address to the site admin address and return the
	 * on-screen message.
	 *
	 * @param string $slug
	 * @return string
	 */
	private function announce_login_url( $slug ) {
		$url  = '' === $slug ? FW_Security_Login_Url::stock_url() : home_url( '/' . $slug );
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = sprintf(
			/* translators: 1: site name, 2: login URL */
			__( "The login page for %1\$s is now:\n\n%2\$s\n\nBookmark it. If you lose it, any of these restores the standard wp-login.php:\n\n- add this line to wp-config.php:  define( 'UPW_SECURITY_LOGIN_SLUG', false );\n- run:  wp upw-security login-url reset\n- deactivate the Security extension.\n", 'fw' ),
			$site,
			$url
		);
		/* translators: %s: site name */
		$sent = wp_mail( get_option( 'admin_email' ), sprintf( __( '[%s] Login address changed', 'fw' ), $site ), $body );

		return '' === $slug
			? __( 'The login page is back at the standard wp-login.php.', 'fw' )
			: sprintf(
				/* translators: 1: URL, 2: sentence about the email */
				__( 'The login page is now %1$s — bookmark it. %2$s If you lose it: define( \'UPW_SECURITY_LOGIN_SLUG\', false ); in wp-config.php, or wp upw-security login-url reset.', 'fw' ),
				$url,
				$sent ? __( 'It was also emailed to the site admin address.', 'fw' ) : __( 'Emailing it to the site admin address failed, so note it now.', 'fw' )
			);
	}

	/* ---------------------------------------------------------------------
	 * Admin page
	 * ------------------------------------------------------------------ */

	/**
	 * @return string
	 */
	public static function page_url() {
		return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
	}

	/**
	 * Render a view file from views/ (render_view() is protected on the base class).
	 *
	 * @param string $name
	 * @param array  $vars
	 * @return string
	 */
	public function view( $name, array $vars = [] ) {
		return $this->render_view( $name, $vars );
	}

	public function _action_admin_menu() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		$this->hook_suffix = add_submenu_page(
			self::PARENT_SLUG,
			__( 'Security', 'fw' ),
			__( 'Security', 'fw' ),
			self::CAPABILITY,
			self::PAGE_SLUG,
			[ $this, 'render_page' ]
		);
		if ( $this->hook_suffix ) {
			add_action( 'load-' . $this->hook_suffix, [ $this, '_maybe_save' ] );
			add_action( 'admin_enqueue_scripts', [ $this, '_enqueue_page' ] );
		}
	}

	/**
	 * @param string[] $order
	 * @return string[]
	 */
	public function _filter_submenu_order( $order ) {
		if ( is_array( $order ) && ! in_array( self::PAGE_SLUG, $order, true ) ) {
			$order[] = self::PAGE_SLUG;
		}

		return $order;
	}

	/**
	 * One settings URL: the manager's generic settings screen for this
	 * extension cannot validate before saving, so it sends people here.
	 */
	public function _redirect_manager_settings_page() {
		if ( wp_doing_ajax() || ! isset( $_GET['page'], $_GET['sub-page'], $_GET['extension'] ) ) {
			return;
		}
		if ( 'fw-extensions' !== $_GET['page'] || 'extension' !== $_GET['sub-page'] || $this->get_name() !== $_GET['extension'] ) {
			return;
		}
		if ( 'settings' !== ( $_GET['tab'] ?? 'settings' ) || ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		wp_safe_redirect( self::page_url() );
		exit;
	}

	/**
	 * Belt and braces: if settings arrive through the manager's generic form
	 * anyway, re-validate them against what was there before and undo anything
	 * invalid.
	 *
	 * @param array $options_before_save
	 */
	public function _after_manager_settings_saved( $options_before_save = [] ) {
		$before         = array_merge( self::defaults(), array_intersect_key( (array) $options_before_save, self::defaults() ) );
		$this->settings = null;
		$new            = $this->get_settings();
		fw_set_db_ext_settings_option( $this->get_name(), null, $before );
		$this->settings = null;
		$result         = $this->save_validated( $new );
		$this->flash( $result['errors'], $result['notes'] );
	}

	/**
	 * @param string $hook
	 */
	public function _enqueue_page( $hook ) {
		if ( $hook !== $this->hook_suffix ) {
			return;
		}
		$ver = $this->manifest->get_version();
		fw()->backend->enqueue_options_static( $this->get_settings_options() );
		wp_enqueue_style( 'upw-sec-admin', fw_min_uri( $this->get_uri( '/static/css/admin.css' ) ), [ 'fw' ], $ver );
		wp_enqueue_script( 'upw-sec-admin', fw_min_uri( $this->get_uri( '/static/js/admin.js' ) ), [ 'jquery', 'fw' ], $ver, true );
	}

	/**
	 * Save handler — on the page's load- hook, before any output.
	 */
	public function _maybe_save() {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		check_admin_referer( self::SETTINGS_NONCE );

		$result = $this->save_validated( fw_get_options_values_from_input( $this->get_settings_options() ) );
		$this->flash( $result['errors'], $result['notes'] );

		$tab = isset( $_POST['upw_tab'] ) ? sanitize_key( $_POST['upw_tab'] ) : '';
		wp_safe_redirect( add_query_arg( 'fw-saved', '1', self::page_url() ) . ( $tab ? '#' . $tab : '' ) );
		exit;
	}

	/**
	 * @param string[] $errors
	 * @param string[] $notes
	 */
	private function flash( array $errors, array $notes ) {
		set_transient( self::NOTICE_KEY . get_current_user_id(), [ 'errors' => $errors, 'notes' => $notes ], 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * admin-post.php?action=upw_security_action&op=…
	 */
	public function _handle_action() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'fw' ), 403 );
		}
		check_admin_referer( self::ACTION_NONCE );
		$op    = isset( $_REQUEST['op'] ) ? sanitize_key( $_REQUEST['op'] ) : '';
		$notes = [];

		switch ( $op ) {
			case 'unlock':
				$key = isset( $_REQUEST['key'] ) ? sanitize_key( $_REQUEST['key'] ) : '';
				$notes[] = FW_Security_Throttle::unlock_key( $key ) ? __( 'Lockout lifted.', 'fw' ) : __( 'That lockout had already ended.', 'fw' );
				break;
			case 'unlock_all':
				/* translators: %d: number */
				$notes[] = sprintf( __( 'Lifted %d lockout(s).', 'fw' ), FW_Security_Throttle::unlock_all() );
				break;
			case 'logout_all':
				FW_Security_Sessions::logout_all();
				wp_safe_redirect( wp_login_url( self::page_url() ) );
				exit;
			case 'probe_uploads':
				$r       = FW_Security_Site_Health::probe_php_in_uploads();
				$notes[] = $r['message'];
				set_transient( 'upw_security_probe', $r, DAY_IN_SECONDS );
				break;
			case 'purge':
				$this->purge_data();
				$notes[] = __( 'All Security data was removed. Every measure is off.', 'fw' );
				break;
		}

		$this->flash( [], $notes );
		wp_safe_redirect( self::page_url() );
		exit;
	}

	/**
	 * @param string $op
	 * @param array  $args
	 * @return string
	 */
	public static function action_url( $op, array $args = [] ) {
		return wp_nonce_url( add_query_arg( [ 'action' => 'upw_security_action', 'op' => $op ] + $args, admin_url( 'admin-post.php' ) ), self::ACTION_NONCE );
	}

	public function render_page() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		$tabs = [];
		foreach ( (array) $this->get_settings_options() as $key => $entry ) {
			if ( is_array( $entry ) && 'tab' === ( $entry['type'] ?? '' ) ) {
				$tabs[ $key ] = $entry;
			}
		}
		$flash = get_transient( self::NOTICE_KEY . get_current_user_id() );
		delete_transient( self::NOTICE_KEY . get_current_user_id() );

		echo $this->view( 'admin-page', [
			'ext'      => $this,
			'tabs'     => $tabs,
			'values'   => $this->get_settings(),
			'flash'    => is_array( $flash ) ? $flash : [ 'errors' => [], 'notes' => [] ],
			'lockouts' => FW_Security_Throttle::lockouts(),
			'probe'    => get_transient( 'upw_security_probe' ),
		] ); // phpcs:ignore WordPress.Security.EscapeOutput
	}

	/* ---------------------------------------------------------------------
	 * Notices
	 * ------------------------------------------------------------------ */

	public function _action_admin_notices() {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			return;
		}
		if ( self::is_safe_mode() ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Security safe mode is on.', 'fw' ) . '</strong> '
				. esc_html__( 'UPW_SECURITY_SAFE_MODE in wp-config.php has switched off every Security measure that changes behaviour. Remove that line once you have regained access.', 'fw' )
				. '</p></div>';
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( get_user_meta( get_current_user_id(), self::INTRO_META, true ) || ( $screen && $screen->id === $this->hook_suffix ) ) {
			return;
		}
		$nonce = wp_create_nonce( 'upw_security_intro' );
		echo '<div class="notice notice-info is-dismissible" data-upw-security-intro="1"><p><strong>'
			. esc_html__( 'Security is active.', 'fw' ) . '</strong> '
			. esc_html__( 'Only read-only checks are running (see Tools → Site Health). Nothing about how people sign in has changed. Each protective measure is a separate switch.', 'fw' )
			. ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Open Security', 'fw' ) . '</a></p></div>'
			. '<script>jQuery(function($){$(document).on("click","[data-upw-security-intro] .notice-dismiss",function(){'
			. '$.post(ajaxurl,{action:"upw_security_dismiss_intro",nonce:"' . esc_js( $nonce ) . '"});});});</script>';
	}

	public function _ajax_dismiss_intro() {
		check_ajax_referer( 'upw_security_intro', 'nonce' );
		update_user_meta( get_current_user_id(), self::INTRO_META, 1 );
		wp_send_json_success();
	}
}

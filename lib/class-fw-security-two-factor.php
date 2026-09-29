<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Two-factor sign-in: an authenticator-app code (TOTP) after the password,
 * with single-use recovery codes.
 *
 * Opt-in per user; the site switch only makes enrolment available. Switching
 * the site off keeps every enrolment and simply stops asking — the fallback
 * direction is always a normal WordPress login.
 *
 * Covered: wp-login.php (and any front-end form that signs in through
 * wp_signon()), XML-RPC password logins (refused for enrolled users, or the
 * second factor would be bypassable there). Not covered, by design:
 * application passwords — scoped, revocable, and unusable on wp-login.php.
 *
 * Secrets are encrypted at rest only when UPW_SECURITY_2FA_KEY is defined.
 * A key derived from the salts was rejected: rotating salts — a normal
 * incident response — would silently break every enrolment.
 */
class FW_Security_Two_Factor {

	const META         = 'upw_sec_2fa';
	const META_PENDING = 'upw_sec_2fa_pending';
	const META_CODES   = 'upw_sec_2fa_recovery';
	const ACTION       = 'upw_2fa';
	const TOKEN_TTL    = 300;
	const MAX_TRIES    = 5;
	const CODE_COUNT   = 10;

	/** @var bool An application password authenticated this request. */
	private static $app_password_used = false;

	/** @var bool Throttling is on, so wrong codes count against it. */
	private static $throttle = false;

	/**
	 * @param bool $throttle
	 */
	public static function init( $throttle ) {
		self::$throttle = (bool) $throttle;

		add_action( 'application_password_did_authenticate', [ __CLASS__, '_note_app_password' ] );
		add_filter( 'authenticate', [ __CLASS__, '_second_step' ], 1000, 1 );
		add_action( 'login_form_' . self::ACTION, [ __CLASS__, '_login_step' ] );
		add_filter( 'wp_login_errors', [ __CLASS__, 'login_messages' ] );

		add_action( 'show_user_profile', [ __CLASS__, '_profile_section' ] );
		add_action( 'edit_user_profile', [ __CLASS__, '_profile_section' ] );
		add_action( 'admin_enqueue_scripts', [ __CLASS__, '_enqueue_profile' ] );

		foreach ( [ 'start', 'confirm', 'disable', 'codes', 'reset' ] as $op ) {
			add_action( 'wp_ajax_upw_sec_2fa_' . $op, [ __CLASS__, '_ajax_' . $op ] );
		}
	}

	/* ---------------------------------------------------------------------
	 * Storage
	 * ------------------------------------------------------------------ */

	/**
	 * @param int $user_id
	 * @return bool
	 */
	public static function is_enrolled( $user_id ) {
		$data = get_user_meta( (int) $user_id, self::META, true );

		return is_array( $data ) && ! empty( $data['secret'] ) && ! empty( $data['confirmed'] );
	}

	/**
	 * @param int $user_id
	 * @return string base32 secret, or '' when it cannot be read
	 */
	private static function secret( $user_id ) {
		$data = get_user_meta( (int) $user_id, self::META, true );
		if ( ! is_array( $data ) || empty( $data['secret'] ) ) {
			return '';
		}

		return empty( $data['enc'] ) ? (string) $data['secret'] : self::decrypt( (string) $data['secret'] );
	}

	/**
	 * @param int    $user_id
	 * @param string $secret
	 */
	private static function store( $user_id, $secret ) {
		$enc = self::has_key();
		update_user_meta( $user_id, self::META, [
			'secret'    => $enc ? self::encrypt( $secret ) : $secret,
			'enc'       => $enc,
			'confirmed' => time(),
			'last_step' => 0,
		] );
	}

	/**
	 * @param int $user_id
	 */
	public static function remove( $user_id ) {
		delete_user_meta( (int) $user_id, self::META );
		delete_user_meta( (int) $user_id, self::META_PENDING );
		delete_user_meta( (int) $user_id, self::META_CODES );
	}

	/**
	 * @return bool
	 */
	public static function has_key() {
		return defined( 'UPW_SECURITY_2FA_KEY' ) && is_string( UPW_SECURITY_2FA_KEY ) && strlen( UPW_SECURITY_2FA_KEY ) >= 16
			&& function_exists( 'openssl_encrypt' );
	}

	/**
	 * @param string $plain
	 * @return string
	 */
	private static function encrypt( $plain ) {
		$key = hash( 'sha256', UPW_SECURITY_2FA_KEY, true );
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );

		return base64_encode( $iv . $tag . $ct );
	}

	/**
	 * @param string $blob
	 * @return string '' when the key is missing or wrong
	 */
	private static function decrypt( $blob ) {
		if ( ! self::has_key() ) {
			return '';
		}
		$raw = base64_decode( $blob, true );
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return '';
		}
		$key   = hash( 'sha256', UPW_SECURITY_2FA_KEY, true );
		$plain = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );

		return false === $plain ? '' : $plain;
	}

	/**
	 * Fresh recovery codes: returned in plain text once, stored as hashes.
	 *
	 * @param int $user_id
	 * @return string[]
	 */
	private static function new_codes( $user_id ) {
		$plain  = [];
		$hashed = [];
		for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
			$code     = strtolower( substr( FW_Security_TOTP::base32_encode( random_bytes( 5 ) ), 0, 8 ) );
			$code     = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
			$plain[]  = $code;
			$hashed[] = wp_hash_password( $code );
		}
		update_user_meta( $user_id, self::META_CODES, $hashed );

		return $plain;
	}

	/**
	 * @param int $user_id
	 * @return int
	 */
	public static function codes_left( $user_id ) {
		$codes = get_user_meta( (int) $user_id, self::META_CODES, true );

		return is_array( $codes ) ? count( $codes ) : 0;
	}

	/**
	 * Check a TOTP code or a recovery code. A used recovery code is removed; a
	 * used TOTP step is remembered, so the same code cannot be replayed.
	 *
	 * @param int    $user_id
	 * @param string $input
	 * @return bool
	 */
	public static function check( $user_id, $input ) {
		$input = strtolower( trim( (string) $input ) );

		if ( preg_match( '/^\d[\d\s]{5,7}$/', $input ) ) {
			$secret = self::secret( $user_id );
			$step   = '' === $secret ? false : FW_Security_TOTP::verify( $secret, $input, time() );
			$data   = get_user_meta( $user_id, self::META, true );
			if ( false === $step || ! is_array( $data ) || $step <= (int) ( $data['last_step'] ?? 0 ) ) {
				return false;
			}
			$data['last_step'] = $step;
			update_user_meta( $user_id, self::META, $data );

			return true;
		}

		$input = preg_replace( '/[^a-z2-7]/', '', $input );
		if ( 8 !== strlen( $input ) ) {
			return false;
		}
		$input = substr( $input, 0, 4 ) . '-' . substr( $input, 4 );
		$codes = get_user_meta( $user_id, self::META_CODES, true );
		foreach ( (array) $codes as $i => $hash ) {
			if ( wp_check_password( $input, $hash ) ) {
				unset( $codes[ $i ] );
				update_user_meta( $user_id, self::META_CODES, array_values( $codes ) );

				return true;
			}
		}

		return false;
	}

	/* ---------------------------------------------------------------------
	 * The login step
	 * ------------------------------------------------------------------ */

	public static function _note_app_password() {
		self::$app_password_used = true;
	}

	/**
	 * After the password (and throttling) have passed: an enrolled user gets
	 * no cookie yet. They are sent to the code step with a short-lived token.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @return WP_User|WP_Error|null
	 */
	public static function _second_step( $user ) {
		if ( ! $user instanceof WP_User || self::$app_password_used || ! self::is_enrolled( $user->ID ) ) {
			return $user;
		}

		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			|| ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			|| wp_doing_ajax()
			|| ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return new WP_Error(
				'upw_2fa_required',
				__( '<strong>Error:</strong> This account uses two-factor sign-in. Sign in through the login page, or use an application password for programs.', 'fw' )
			);
		}

		$token = bin2hex( random_bytes( 20 ) );
		set_transient( 'upw_sec_2fa_' . hash( 'sha256', $token ), [
			'user'        => $user->ID,
			'remember'    => ! empty( $_POST['rememberme'] ),
			'redirect_to' => isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '',
			'interim'     => ! empty( $_REQUEST['interim-login'] ),
			'tries'       => 0,
		], self::TOKEN_TTL );

		$args = [ 'action' => self::ACTION, 'upw_2fa_token' => $token ];
		if ( ! empty( $_REQUEST['interim-login'] ) ) {
			$args['interim-login'] = 1;
		}
		wp_safe_redirect( add_query_arg( $args, wp_login_url() ) );
		exit;
	}

	/**
	 * wp-login.php?action=upw_2fa — show the code form, check a submitted code.
	 */
	public static function _login_step() {
		$token = isset( $_REQUEST['upw_2fa_token'] ) ? preg_replace( '/[^a-f0-9]/', '', (string) $_REQUEST['upw_2fa_token'] ) : '';
		$key   = 'upw_sec_2fa_' . hash( 'sha256', $token );
		$state = '' === $token ? false : get_transient( $key );

		if ( ! is_array( $state ) || empty( $state['user'] ) ) {
			wp_safe_redirect( add_query_arg( 'upw_2fa', 'expired', wp_login_url() ) );
			exit;
		}

		$user  = get_userdata( (int) $state['user'] );
		$error = '';

		if ( 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && $user ) {
			$locked = self::$throttle ? FW_Security_Throttle::locked_for( $user->user_login ) : 0;

			if ( $locked > 0 ) {
				delete_transient( $key );
				wp_safe_redirect( wp_login_url() );
				exit;
			}

			if ( self::check( $user->ID, isset( $_POST['upw_2fa_code'] ) ? wp_unslash( $_POST['upw_2fa_code'] ) : '' ) ) {
				delete_transient( $key );
				self::finish_login( $user, $state );
			}

			if ( self::$throttle ) {
				FW_Security_Throttle::record_failure( $user->user_login );
			}
			++$state['tries'];
			if ( $state['tries'] >= self::MAX_TRIES ) {
				delete_transient( $key );
				wp_safe_redirect( add_query_arg( 'upw_2fa', 'too-many', wp_login_url() ) );
				exit;
			}
			set_transient( $key, $state, self::TOKEN_TTL );
			$error = __( 'That code is not correct. Check your authenticator app and try again, or enter a recovery code.', 'fw' );
		}

		self::render_form( $token, $state, $error );
		exit;
	}

	/**
	 * @param WP_User $user
	 * @param array   $state
	 */
	private static function finish_login( WP_User $user, array $state ) {
		wp_set_auth_cookie( $user->ID, ! empty( $state['remember'] ) );
		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user );

		if ( ! empty( $state['interim'] ) ) {
			global $interim_login;
			$interim_login = 'success';
			login_header( '', '<p class="message">' . esc_html__( 'You have logged in successfully.', 'fw' ) . '</p>' );
			echo '</div>';
			/** This action is documented in wp-login.php */
			do_action( 'login_footer' );
			echo '</body></html>';
			exit;
		}

		$requested = (string) $state['redirect_to'];
		$redirect  = '' !== $requested ? $requested : admin_url();
		/** This filter is documented in wp-login.php */
		$redirect = apply_filters( 'login_redirect', $redirect, $requested, $user );

		if ( ( '' === $requested || admin_url() === $redirect ) && ! $user->has_cap( 'read' ) ) {
			$redirect = home_url();
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * @param string $token
	 * @param array  $state
	 * @param string $error
	 */
	private static function render_form( $token, array $state, $error ) {
		global $interim_login;
		if ( ! empty( $state['interim'] ) ) {
			$interim_login = true;
		}

		$errors = new WP_Error();
		if ( '' !== $error ) {
			$errors->add( 'upw_2fa_invalid', $error );
		}

		login_header( __( 'Two-factor sign-in', 'fw' ), '', $errors );
		?>
		<form name="upw_2fa_form" id="loginform" action="<?php echo esc_url( add_query_arg( 'action', self::ACTION, wp_login_url() ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Enter the 6-digit code from your authenticator app. Lost your device? Enter one of your recovery codes instead.', 'fw' ); ?></p>
			<p>
				<label for="upw_2fa_code"><?php esc_html_e( 'Code', 'fw' ); ?></label>
				<input type="text" name="upw_2fa_code" id="upw_2fa_code" class="input" value="" size="20"
					autocomplete="one-time-code" inputmode="text" spellcheck="false" autocapitalize="off" autofocus required>
			</p>
			<input type="hidden" name="upw_2fa_token" value="<?php echo esc_attr( $token ); ?>">
			<?php if ( ! empty( $state['interim'] ) ) : ?>
				<input type="hidden" name="interim-login" value="1">
			<?php endif; ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'fw' ); ?>">
			</p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '&larr; Back to sign in', 'fw' ); ?></a></p>
		<?php
		login_footer( 'upw_2fa_code' );
	}

	/**
	 * A message on the login screen after an expired or exhausted code step.
	 *
	 * @param WP_Error $errors
	 * @return WP_Error
	 */
	public static function login_messages( $errors ) {
		$flag = isset( $_GET['upw_2fa'] ) ? (string) $_GET['upw_2fa'] : '';
		if ( 'expired' === $flag ) {
			$errors->add( 'upw_2fa_expired', __( 'The sign-in step expired. Please sign in again.', 'fw' ), 'message' );
		} elseif ( 'too-many' === $flag ) {
			$errors->add( 'upw_2fa_too_many', __( 'Too many wrong codes. Please sign in again.', 'fw' ) );
		}

		return $errors;
	}

	/* ---------------------------------------------------------------------
	 * Profile screen
	 * ------------------------------------------------------------------ */

	/**
	 * @param string $hook
	 */
	public static function _enqueue_profile( $hook ) {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}
		$ext = fw_ext( 'security' );
		$ver = $ext ? $ext->manifest->get_version() : '1';
		wp_enqueue_script( 'upw-sec-qrcode', fw_min_uri( $ext->get_uri( '/static/js/vendor/qrcode.js' ) ), [], '2.0.4', true );
		wp_enqueue_script( 'upw-sec-profile-2fa', fw_min_uri( $ext->get_uri( '/static/js/profile-2fa.js' ) ), [ 'jquery', 'upw-sec-qrcode', 'fw' ], $ver, true );
		wp_enqueue_style( 'upw-sec-admin', fw_min_uri( $ext->get_uri( '/static/css/admin.css' ) ), [ 'fw' ], $ver );
		wp_localize_script( 'upw-sec-profile-2fa', 'upwSec2fa', [
			'failed'     => __( 'Something went wrong. Reload the page and try again.', 'fw' ),
			'on'         => __( 'Two-factor sign-in is on.', 'fw' ),
			'newCodes'   => __( 'New recovery codes created. The old ones no longer work.', 'fw' ),
			'confirmOff' => __( 'Turn off two-factor sign-in? You will sign in with just your password.', 'fw' ),
			'copied'     => __( 'Copied.', 'fw' ),
		] );
	}

	/**
	 * @param WP_User $profile_user
	 */
	public static function _profile_section( $profile_user ) {
		$is_self = get_current_user_id() === (int) $profile_user->ID;
		if ( ! $is_self && ! current_user_can( 'edit_user', $profile_user->ID ) ) {
			return;
		}
		$ext = fw_ext( 'security' );
		echo $ext->view( 'profile-two-factor', [
			'user'     => $profile_user,
			'is_self'  => $is_self,
			'enrolled' => self::is_enrolled( $profile_user->ID ),
			'left'     => self::codes_left( $profile_user->ID ),
			'since'    => (int) ( get_user_meta( $profile_user->ID, self::META, true )['confirmed'] ?? 0 ),
			'readable' => '' !== self::secret( $profile_user->ID ) || ! self::is_enrolled( $profile_user->ID ),
			'nonce'    => wp_create_nonce( 'upw_sec_2fa_' . $profile_user->ID ),
		] ); // phpcs:ignore WordPress.Security.EscapeOutput
	}

	/**
	 * Common AJAX guard: nonce bound to the target user, and either the user
	 * themself or (for reset only) someone allowed to edit them.
	 *
	 * @param bool $admin_reset
	 * @return int target user id
	 */
	private static function ajax_user( $admin_reset = false ) {
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0;
		check_ajax_referer( 'upw_sec_2fa_' . $user_id, 'nonce' );

		$is_self = get_current_user_id() === $user_id;
		if ( $admin_reset ? ( $is_self || ! current_user_can( 'edit_user', $user_id ) ) : ! $is_self ) {
			wp_send_json_error( [ 'message' => __( 'You are not allowed to do that.', 'fw' ) ], 403 );
		}

		return $user_id;
	}

	public static function _ajax_start() {
		$user_id = self::ajax_user();
		if ( self::is_enrolled( $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Two-factor sign-in is already on.', 'fw' ) ] );
		}
		$secret = FW_Security_TOTP::new_secret();
		update_user_meta( $user_id, self::META_PENDING, [ 'secret' => $secret, 'at' => time() ] );
		$user = get_userdata( $user_id );

		wp_send_json_success( [
			'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
			'uri'    => FW_Security_TOTP::uri( $secret, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ?: wp_parse_url( home_url(), PHP_URL_HOST ) ),
		] );
	}

	public static function _ajax_confirm() {
		$user_id = self::ajax_user();
		$pending = get_user_meta( $user_id, self::META_PENDING, true );
		if ( ! is_array( $pending ) || empty( $pending['secret'] ) || ( time() - (int) $pending['at'] ) > HOUR_IN_SECONDS ) {
			wp_send_json_error( [ 'message' => __( 'Setup expired. Start again.', 'fw' ) ] );
		}
		$code = isset( $_POST['code'] ) ? (string) wp_unslash( $_POST['code'] ) : '';
		$step = FW_Security_TOTP::verify( $pending['secret'], $code, time() );
		if ( false === $step ) {
			wp_send_json_error( [ 'message' => __( 'That code is not correct. Check the time on your phone is set automatically, then try the next code.', 'fw' ) ] );
		}
		self::store( $user_id, $pending['secret'] );
		$data              = get_user_meta( $user_id, self::META, true );
		$data['last_step'] = $step;
		update_user_meta( $user_id, self::META, $data );
		delete_user_meta( $user_id, self::META_PENDING );

		wp_send_json_success( [ 'codes' => self::new_codes( $user_id ) ] );
	}

	/**
	 * Turning it off or replacing the recovery codes needs a current code, so a
	 * hijacked session cannot quietly remove the second factor.
	 */
	private static function require_current_code( $user_id ) {
		$code = isset( $_POST['code'] ) ? (string) wp_unslash( $_POST['code'] ) : '';
		if ( ! self::check( $user_id, $code ) ) {
			wp_send_json_error( [ 'message' => __( 'Enter a current code from your app (or a recovery code) to confirm.', 'fw' ) ] );
		}
	}

	public static function _ajax_disable() {
		$user_id = self::ajax_user();
		self::require_current_code( $user_id );
		self::remove( $user_id );
		wp_send_json_success();
	}

	public static function _ajax_codes() {
		$user_id = self::ajax_user();
		self::require_current_code( $user_id );
		wp_send_json_success( [ 'codes' => self::new_codes( $user_id ) ] );
	}

	public static function _ajax_reset() {
		$user_id = self::ajax_user( true );
		self::remove( $user_id );
		wp_send_json_success();
	}
}

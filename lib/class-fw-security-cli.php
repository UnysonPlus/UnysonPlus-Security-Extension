<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Recovery and inspection from the command line. Every command works in safe
 * mode, and none needs a logged-in administrator — which is the point.
 */
class FW_Security_CLI {

	public static function register() {
		WP_CLI::add_command( 'upw-security', __CLASS__ );
		WP_CLI::add_command( 'upw-security login-url', 'FW_Security_CLI_Login_Url' );
		WP_CLI::add_command( 'upw-security 2fa', 'FW_Security_CLI_Two_Factor' );
	}

	/**
	 * @return FW_Extension_Security
	 */
	public static function ext() {
		return fw_ext( 'security' );
	}

	/**
	 * Show every measure: saved state, and whether safe mode or a constant overrides it.
	 *
	 * ## EXAMPLES
	 *
	 *     wp upw-security status
	 *
	 * @when after_wp_load
	 */
	public function status() {
		$ext  = self::ext();
		$rows = [];
		foreach ( FW_Extension_Security::MEASURES as $key => $label ) {
			$saved  = $ext->setting( $key );
			$rows[] = [
				'measure' => $label,
				'saved'   => is_bool( $saved ) ? ( $saved ? 'on' : 'off' ) : ( '' === $saved ? 'off' : (string) $saved ),
				'running' => $ext->measure_running( $key ) ? 'yes' : 'no',
			];
		}
		WP_CLI\Utils\format_items( 'table', $rows, [ 'measure', 'saved', 'running' ] );

		if ( FW_Extension_Security::is_safe_mode() ) {
			WP_CLI::warning( 'Safe mode is on (UPW_SECURITY_SAFE_MODE): nothing that changes behaviour is running.' );
		}
		if ( defined( 'UPW_SECURITY_LOGIN_SLUG' ) ) {
			WP_CLI::log( 'The login address is set by UPW_SECURITY_LOGIN_SLUG in wp-config.php.' );
		}
		$lockouts = FW_Security_Throttle::lockouts();
		WP_CLI::log( sprintf( 'Active lockouts: %d', count( $lockouts ) ) );
	}

	/**
	 * Turn one measure, or every measure, off in the saved settings.
	 *
	 * ## OPTIONS
	 *
	 * [<measure>]
	 * : One of: throttle, errors, 2fa, xmlrpc, headers, user-listing, login-url.
	 *
	 * [--all]
	 * : Turn every measure off.
	 *
	 * ## EXAMPLES
	 *
	 *     wp upw-security disable login-url
	 *     wp upw-security disable --all
	 *
	 * @when after_wp_load
	 */
	public function disable( $args, $assoc ) {
		$map = [
			'throttle'     => [ 'throttle_enabled' => false ],
			'errors'       => [ 'generic_login_errors' => false ],
			'2fa'          => [ 'twofa_enabled' => false ],
			'xmlrpc'       => [ 'xmlrpc_mode' => 'leave' ],
			'headers'      => [ 'hdr_frame' => false, 'hdr_nosniff' => false, 'hdr_referrer' => 'off', 'hdr_hsts' => false ],
			'user-listing' => [ 'limit_user_listing' => false ],
			'login-url'    => [ 'login_slug' => '' ],
		];
		if ( ! empty( $assoc['all'] ) ) {
			$changes = array_merge( ...array_values( $map ) );
		} elseif ( isset( $args[0], $map[ $args[0] ] ) ) {
			$changes = $map[ $args[0] ];
		} else {
			WP_CLI::error( 'Name a measure (' . implode( ', ', array_keys( $map ) ) . ') or pass --all.' );
		}
		self::ext()->save_settings( $changes );
		WP_CLI::success( 'Turned off.' );
	}

	/**
	 * Lift login lockouts.
	 *
	 * ## OPTIONS
	 *
	 * [--ip=<ip>]
	 * : Lift every lockout for this address.
	 *
	 * [--all]
	 * : Lift every lockout.
	 *
	 * ## EXAMPLES
	 *
	 *     wp upw-security unlock --ip=203.0.113.7
	 *     wp upw-security unlock --all
	 *
	 * @when after_wp_load
	 */
	public function unlock( $args, $assoc ) {
		if ( ! empty( $assoc['all'] ) ) {
			WP_CLI::success( sprintf( 'Lifted %d lockout(s).', FW_Security_Throttle::unlock_all() ) );

			return;
		}
		if ( empty( $assoc['ip'] ) || ! filter_var( $assoc['ip'], FILTER_VALIDATE_IP ) ) {
			WP_CLI::error( 'Pass --ip=<address> or --all.' );
		}
		WP_CLI::success( sprintf( 'Lifted %d lockout(s) for %s.', FW_Security_Throttle::unlock_ip( $assoc['ip'] ), $assoc['ip'] ) );
	}

	/**
	 * Sign every user out, everywhere.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation.
	 *
	 * @subcommand logout-all
	 * @when after_wp_load
	 */
	public function logout_all( $args, $assoc ) {
		WP_CLI::confirm( 'Every user, including you, will need to sign in again. Continue?', $assoc );
		WP_CLI::success( sprintf( 'Signed out %d user(s).', FW_Security_Sessions::logout_all() ) );
	}

	/**
	 * Remove all Security data: settings, lockouts and two-factor enrolments.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation.
	 *
	 * @when after_wp_load
	 */
	public function purge( $args, $assoc ) {
		WP_CLI::confirm( 'This removes every Security setting, lockout and two-factor enrolment. Continue?', $assoc );
		self::ext()->purge_data();
		WP_CLI::success( 'Security data removed.' );
	}
}

/**
 * wp upw-security login-url …
 */
class FW_Security_CLI_Login_Url {

	/**
	 * Print the current login address.
	 *
	 * @when after_wp_load
	 */
	public function get() {
		$slug = FW_Security_CLI::ext()->login_slug();
		WP_CLI::log( '' === $slug ? FW_Security_Login_Url::stock_url() . '  (standard address)' : home_url( '/' . $slug ) );
		if ( defined( 'UPW_SECURITY_LOGIN_SLUG' ) ) {
			WP_CLI::log( '(set by UPW_SECURITY_LOGIN_SLUG in wp-config.php)' );
		}
	}

	/**
	 * Go back to the standard wp-login.php address.
	 *
	 * @when after_wp_load
	 */
	public function reset() {
		FW_Security_CLI::ext()->save_settings( [ 'login_slug' => '' ] );
		if ( defined( 'UPW_SECURITY_LOGIN_SLUG' ) && UPW_SECURITY_LOGIN_SLUG ) {
			WP_CLI::warning( 'UPW_SECURITY_LOGIN_SLUG in wp-config.php still overrides the saved setting. Remove it (or set it to false).' );
		}
		WP_CLI::success( 'Login page is back at ' . FW_Security_Login_Url::stock_url() );
	}

	/**
	 * Set a custom login address. Runs the same checks as the settings screen.
	 *
	 * ## OPTIONS
	 *
	 * <slug>
	 * : Lowercase letters, digits and hyphens.
	 *
	 * @when after_wp_load
	 */
	public function set( $args ) {
		$slug   = strtolower( trim( (string) $args[0], "/ \t" ) );
		$errors = FW_Security_Slug_Rules::errors( $slug );
		if ( $errors ) {
			WP_CLI::error( implode( "\n", $errors ) );
		}
		FW_Security_CLI::ext()->save_settings( [ 'login_slug' => $slug ] );
		WP_CLI::success( 'Login page: ' . home_url( '/' . $slug ) );
	}
}

/**
 * wp upw-security 2fa …
 */
class FW_Security_CLI_Two_Factor {

	/**
	 * Remove a user's two-factor enrolment so they can sign in with a password.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * @when after_wp_load
	 */
	public function reset( $args ) {
		$u    = $args[0];
		$user = is_numeric( $u ) ? get_userdata( (int) $u ) : ( get_user_by( 'login', $u ) ?: get_user_by( 'email', $u ) );
		if ( ! $user ) {
			WP_CLI::error( 'No such user.' );
		}
		FW_Security_Two_Factor::remove( $user->ID );
		WP_CLI::success( sprintf( 'Two-factor sign-in removed for %s. They can set it up again from their profile.', $user->user_login ) );
	}

	/**
	 * List users who have two-factor sign-in set up.
	 *
	 * @when after_wp_load
	 */
	public function list() {
		$ids  = get_users( [ 'meta_key' => FW_Security_Two_Factor::META, 'fields' => 'ID' ] );
		$rows = [];
		foreach ( $ids as $id ) {
			if ( FW_Security_Two_Factor::is_enrolled( $id ) ) {
				$u      = get_userdata( $id );
				$rows[] = [ 'ID' => $id, 'login' => $u->user_login, 'recovery_codes_left' => FW_Security_Two_Factor::codes_left( $id ) ];
			}
		}
		WP_CLI\Utils\format_items( 'table', $rows, [ 'ID', 'login', 'recovery_codes_left' ] );
	}
}

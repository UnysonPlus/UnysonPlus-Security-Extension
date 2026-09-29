<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Login throttling.
 *
 * Two counters per failed attempt, both keyed by a salted hash of the address:
 *
 *   - address + username ("iu"): the normal case — someone guessing one account.
 *     Reaching the limit cools down that pair only, so a colleague behind the
 *     same office address can still sign in to their own account.
 *   - address alone ("ip"): a looser ceiling that catches one address spraying
 *     many usernames.
 *
 * Never per username alone: that would let anyone lock the administrator out
 * by guessing badly on purpose.
 *
 * Cooldowns double on each repeat within a day and are capped, so the worst
 * case is always waiting. Nothing is permanent.
 *
 * Covered entry points: wp-login.php and XML-RPC logins (both through the core
 * `authenticate` filter), and REST Basic auth with an application password,
 * which core checks through wp_authenticate_application_password() directly
 * and reports on its own action.
 */
class FW_Security_Throttle {

	const LOCKOUTS_OPTION = 'upw_security_lockouts';
	const LOCKOUTS_CAP    = 200;
	const IP_MULTIPLIER   = 4;
	const LOCKED_CODE     = 'upw_security_locked';
	const GENERIC_CODE    = 'upw_security_invalid_login';

	/** @var array */
	private static $s = [];

	/** @var string[] */
	private static $allowlist = [];

	/**
	 * @param array $settings
	 */
	public static function init( array $settings ) {
		self::$s         = $settings;
		self::$allowlist = FW_Security_IP::parse_list( (string) ( $settings['throttle_allowlist'] ?? '' ) )['valid'];

		add_action( 'wp_login_failed', [ __CLASS__, '_on_login_failed' ], 10, 2 );
		add_action( 'application_password_failed_authentication', [ __CLASS__, '_on_app_password_failed' ] );
		add_filter( 'authenticate', [ __CLASS__, '_refuse_if_locked' ], 999, 3 );
		add_action( 'wp_authenticate_application_password_errors', [ __CLASS__, '_refuse_app_password_if_locked' ], 10, 2 );
		add_action( 'wp_login', [ __CLASS__, '_on_login' ], 10, 1 );
		add_filter( 'shake_error_codes', [ __CLASS__, '_shake_codes' ] );
	}

	/* ---------------------------------------------------------------------
	 * Hooks
	 * ------------------------------------------------------------------ */

	/**
	 * @param string        $username
	 * @param WP_Error|null $error
	 */
	public static function _on_login_failed( $username, $error = null ) {
		if ( $error instanceof WP_Error && self::LOCKED_CODE === $error->get_error_code() ) {
			return; // a refused attempt while cooling down is not a new guess
		}
		self::record_failure( (string) $username );
	}

	/**
	 * @param WP_Error $error
	 */
	public static function _on_app_password_failed( $error ) {
		// Inside the `authenticate` filter (wp-login.php, XML-RPC) the same
		// failure is counted by wp_login_failed, with the real username. Only
		// the REST Basic-auth path calls the application-password check
		// directly, so only there is it counted here.
		if ( doing_filter( 'authenticate' ) ) {
			return;
		}
		$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';
		self::record_failure( $username );
	}

	/**
	 * Runs after core has checked the password. While cooling down, any result
	 * — including a correct password — becomes the lockout error. Letting a
	 * correct password through would tell an attacker exactly when a guess was
	 * right.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public static function _refuse_if_locked( $user, $username = '', $password = '' ) {
		if ( null === $user && '' === (string) $username ) {
			return $user; // an empty form, nothing attempted
		}
		$remaining = self::locked_for( (string) $username );
		if ( $remaining > 0 ) {
			return self::locked_error( $remaining );
		}

		return $user;
	}

	/**
	 * @param WP_Error $error
	 * @param WP_User  $user
	 */
	public static function _refuse_app_password_if_locked( $error, $user ) {
		$remaining = self::locked_for( $user instanceof WP_User ? $user->user_login : '' );
		if ( $remaining > 0 ) {
			$error->add( self::LOCKED_CODE, self::locked_error( $remaining )->get_error_message() );
		}
	}

	/**
	 * A successful sign-in clears that address + username pair.
	 *
	 * @param string $user_login
	 */
	public static function _on_login( $user_login ) {
		$ip = FW_Security_IP::client_ip();
		delete_transient( 'upw_sec_f_' . self::key( 'iu', $ip, $user_login ) );
	}

	/**
	 * @param string[] $codes
	 * @return string[]
	 */
	public static function _shake_codes( $codes ) {
		$codes[] = self::LOCKED_CODE;
		$codes[] = self::GENERIC_CODE;

		return $codes;
	}

	/* ---------------------------------------------------------------------
	 * Counting and cooling down
	 * ------------------------------------------------------------------ */

	/**
	 * Count one failed attempt — also used by the two-factor step for wrong codes.
	 *
	 * @param string $username
	 */
	public static function record_failure( $username ) {
		$ip = FW_Security_IP::client_ip();
		if ( '' === $ip || FW_Security_IP::on_list( $ip, self::$allowlist ) ) {
			return;
		}

		$username = self::clean_username( $username );
		$limit    = max( 1, (int) ( self::$s['throttle_attempts'] ?? 5 ) );
		$window   = max( 60, (int) ( self::$s['throttle_window'] ?? 15 ) * MINUTE_IN_SECONDS );

		if ( self::bump( self::key( 'iu', $ip, $username ), $window ) >= $limit ) {
			self::lock( 'iu', $ip, $username );
		}
		if ( self::bump( self::key( 'ip', $ip ), $window ) >= $limit * self::IP_MULTIPLIER ) {
			self::lock( 'ip', $ip, '' );
		}
	}

	/**
	 * Seconds left on whichever cooldown applies to this address (+ username).
	 *
	 * @param string $username
	 * @return int
	 */
	public static function locked_for( $username ) {
		$ip = FW_Security_IP::client_ip();
		if ( '' === $ip || FW_Security_IP::on_list( $ip, self::$allowlist ) ) {
			return 0;
		}

		$now  = time();
		$best = 0;
		foreach ( [ self::key( 'ip', $ip ), self::key( 'iu', $ip, self::clean_username( $username ) ) ] as $key ) {
			$lock = get_transient( 'upw_sec_l_' . $key );
			if ( is_array( $lock ) && ! empty( $lock['until'] ) && $lock['until'] > $now ) {
				$best = max( $best, $lock['until'] - $now );
			}
		}

		return $best;
	}

	/**
	 * Cooldown length for the n-th lock within a day: base × 2^(n−1), capped.
	 *
	 * @param int $level 1-based
	 * @param int $base  seconds
	 * @param int $cap   seconds
	 * @return int
	 */
	public static function lock_duration( $level, $base, $cap ) {
		$level = max( 1, (int) $level );
		// 2^20 is already far beyond any sensible cap; stop doubling there.
		$factor = 2 ** min( $level - 1, 20 );

		return (int) min( $cap, $base * $factor );
	}

	/**
	 * @param string $scope    'ip' | 'iu'
	 * @param string $ip
	 * @param string $username
	 */
	private static function lock( $scope, $ip, $username ) {
		$key   = self::key( $scope, $ip, $username );
		$level = (int) get_transient( 'upw_sec_lv_' . $key ) + 1;
		$base  = max( 60, (int) ( self::$s['throttle_lockout'] ?? 15 ) * MINUTE_IN_SECONDS );
		$cap   = max( $base, (int) ( self::$s['throttle_lockout_max'] ?? 12 ) * HOUR_IN_SECONDS );
		$secs  = self::lock_duration( $level, $base, $cap );
		$until = time() + $secs;

		set_transient( 'upw_sec_l_' . $key, [ 'until' => $until ], $secs );
		set_transient( 'upw_sec_lv_' . $key, $level, DAY_IN_SECONDS );
		delete_transient( 'upw_sec_f_' . $key ); // start the next window clean

		self::remember( $key, [
			'scope'   => $scope,
			'ip_hash' => FW_Security_IP::hash( $ip ),
			'label'   => FW_Security_IP::mask( $ip ),
			'user'    => $username,
			'until'   => $until,
			'level'   => $level,
		] );
	}

	/**
	 * Increment a counter inside a fixed window measured from its first hit.
	 *
	 * @param string $key
	 * @param int    $window seconds
	 * @return int the new count
	 */
	private static function bump( $key, $window ) {
		$t    = 'upw_sec_f_' . $key;
		$data = get_transient( $t );
		$now  = time();

		if ( ! is_array( $data ) || empty( $data['exp'] ) || $data['exp'] <= $now ) {
			$data = [ 'n' => 0, 'exp' => $now + $window ];
		}
		++$data['n'];

		// Carry the window's remaining time, never 0: an expiry of 0 means
		// "never expire", which would make the counter permanent.
		set_transient( $t, $data, max( 1, $data['exp'] - $now ) );

		return (int) $data['n'];
	}

	/**
	 * @param string $scope
	 * @param string $ip
	 * @param string $username
	 * @return string
	 */
	private static function key( $scope, $ip, $username = '' ) {
		return $scope . '_' . substr( md5( FW_Security_IP::hash( $ip ) . '|' . ( 'iu' === $scope ? strtolower( $username ) : '' ) ), 0, 24 );
	}

	/**
	 * @param string $username
	 * @return string
	 */
	private static function clean_username( $username ) {
		return substr( sanitize_user( (string) $username, true ), 0, 60 );
	}

	/**
	 * @param int $seconds
	 * @return WP_Error
	 */
	private static function locked_error( $seconds ) {
		$minutes = max( 1, (int) ceil( $seconds / 60 ) );

		return new WP_Error(
			self::LOCKED_CODE,
			sprintf(
				/* translators: %s: a duration such as "15 minutes" */
				__( '<strong>Error:</strong> Too many failed sign-in attempts. Please try again in %s.', 'fw' ),
				$minutes >= 120
					/* translators: %d: hours */
					? sprintf( _n( '%d hour', '%d hours', (int) ceil( $minutes / 60 ), 'fw' ), (int) ceil( $minutes / 60 ) )
					/* translators: %d: minutes */
					: sprintf( _n( '%d minute', '%d minutes', $minutes, 'fw' ), $minutes )
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * The lockout list (for the Status tab and WP-CLI)
	 * ------------------------------------------------------------------ */

	/**
	 * @param string $key
	 * @param array  $entry
	 */
	private static function remember( $key, array $entry ) {
		$list         = self::lockouts();
		$list[ $key ] = $entry;

		// Keep the newest entries only; this is a working list, not a log.
		uasort( $list, static fn( $a, $b ) => $b['until'] <=> $a['until'] );
		$list = array_slice( $list, 0, self::LOCKOUTS_CAP, true );

		update_option( self::LOCKOUTS_OPTION, $list, false );
	}

	/**
	 * Active lockouts, newest first. Expired entries are dropped on read.
	 *
	 * @return array<string, array>
	 */
	public static function lockouts() {
		$list = get_option( self::LOCKOUTS_OPTION, [] );
		if ( ! is_array( $list ) ) {
			return [];
		}
		$now = time();

		return array_filter( $list, static fn( $e ) => is_array( $e ) && ( $e['until'] ?? 0 ) > $now );
	}

	/**
	 * Lift one lockout by its key.
	 *
	 * @param string $key
	 * @return bool
	 */
	public static function unlock_key( $key ) {
		$list = self::lockouts();
		if ( ! isset( $list[ $key ] ) ) {
			return false;
		}
		self::forget( $key );
		unset( $list[ $key ] );
		update_option( self::LOCKOUTS_OPTION, $list, false );

		return true;
	}

	/**
	 * Lift every lockout (both scopes) for one address.
	 *
	 * @param string $ip
	 * @return int number lifted
	 */
	public static function unlock_ip( $ip ) {
		$hash  = FW_Security_IP::hash( $ip );
		$list  = self::lockouts();
		$count = 0;
		foreach ( $list as $key => $entry ) {
			if ( ( $entry['ip_hash'] ?? '' ) === $hash ) {
				self::forget( $key );
				unset( $list[ $key ] );
				++$count;
			}
		}
		// The address-wide counter may be mid-window without a lock yet.
		self::forget( self::key( 'ip', $ip ) );
		update_option( self::LOCKOUTS_OPTION, $list, false );

		return $count;
	}

	/**
	 * Lift every lockout.
	 *
	 * @return int number lifted
	 */
	public static function unlock_all() {
		$list = self::lockouts();
		foreach ( array_keys( $list ) as $key ) {
			self::forget( $key );
		}
		delete_option( self::LOCKOUTS_OPTION );

		return count( $list );
	}

	/**
	 * @param string $key
	 */
	private static function forget( $key ) {
		delete_transient( 'upw_sec_l_' . $key );
		delete_transient( 'upw_sec_lv_' . $key );
		delete_transient( 'upw_sec_f_' . $key );
	}
}

/**
 * Generic login errors: one message whether the username or the password was
 * wrong, so the login form stops confirming which accounts exist.
 *
 * It closes one path of several — the lost-password form, author archives and
 * the REST API can still reveal usernames — and the option says so.
 */
class FW_Security_Login_Errors {

	const CODES = [ 'invalid_username', 'invalid_email', 'incorrect_password' ];

	public static function init() {
		add_filter( 'authenticate', [ __CLASS__, '_generic' ], 100, 1 );
		add_filter( 'shake_error_codes', [ __CLASS__, '_shake_codes' ] );
	}

	/**
	 * @param WP_User|WP_Error|null $user
	 * @return WP_User|WP_Error|null
	 */
	public static function _generic( $user ) {
		if ( ! $user instanceof WP_Error ) {
			return $user;
		}
		if ( ! array_intersect( $user->get_error_codes(), self::CODES ) ) {
			return $user;
		}

		return new WP_Error(
			FW_Security_Throttle::GENERIC_CODE,
			sprintf(
				/* translators: %s: lost password URL */
				__( '<strong>Error:</strong> The username, email address or password is not correct. <a href="%s">Lost your password?</a>', 'fw' ),
				esc_url( wp_lostpassword_url() )
			)
		);
	}

	/**
	 * @param string[] $codes
	 * @return string[]
	 */
	public static function _shake_codes( $codes ) {
		$codes[] = FW_Security_Throttle::GENERIC_CODE;

		return $codes;
	}
}

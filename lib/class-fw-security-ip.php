<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Client address resolution for the Security extension.
 *
 * REMOTE_ADDR is the only address a visitor cannot forge, so it is the
 * default. Behind a reverse proxy or CDN, though, REMOTE_ADDR is the proxy and
 * every visitor shares it — throttling on it would lock everyone out at once.
 * A forwarding header fixes that, but only when it is read from a proxy we
 * trust: anyone can send `X-Forwarded-For`, and trusting it blindly lets an
 * attacker pick a fresh address per request.
 *
 * So a header is honoured only when the site owner has chosen one AND the
 * request arrived from a trusted proxy address. With no trusted list, only
 * private and loopback proxies count (a proxy on the same network).
 */
class FW_Security_IP {

	/** Headers that indicate a proxy sits in front of the site. */
	const FORWARDING_HEADERS = [
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_REAL_IP',
		'HTTP_FORWARDED',
		'HTTP_TRUE_CLIENT_IP',
		'HTTP_X_CLIENT_IP',
	];

	/** @var string 'none' | 'x-forwarded-for' | 'x-real-ip' | 'custom' */
	private static $header = 'none';

	/** @var string Server key for a custom header, e.g. HTTP_X_VISITOR_IP. */
	private static $custom_header = '';

	/** @var string[] Trusted proxy addresses / CIDR ranges. */
	private static $trusted = [];

	/**
	 * Apply the saved proxy configuration. Also feeds the framework's shared
	 * rate limiter, so its per-visitor counters see real visitors too.
	 *
	 * @param array $settings
	 */
	public static function configure( array $settings ) {
		self::$header        = (string) ( $settings['proxy_header'] ?? 'none' );
		self::$custom_header = self::server_key( (string) ( $settings['proxy_header_custom'] ?? '' ) );
		self::$trusted       = self::parse_list( (string) ( $settings['proxy_trusted'] ?? '' ) )['valid'];

		if ( 'none' !== self::$header ) {
			add_filter( 'fw_rate_limit_client_ip', [ __CLASS__, 'client_ip' ] );
		}
	}

	/**
	 * The visitor's address, honouring a trusted proxy header when configured.
	 *
	 * @return string
	 */
	public static function client_ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';

		if ( 'none' === self::$header || ! self::is_trusted_proxy( $remote ) ) {
			return $remote;
		}

		$key = [
			'x-forwarded-for' => 'HTTP_X_FORWARDED_FOR',
			'x-real-ip'       => 'HTTP_X_REAL_IP',
			'custom'          => self::$custom_header,
		][ self::$header ] ?? '';

		if ( '' === $key || empty( $_SERVER[ $key ] ) ) {
			return $remote;
		}

		// A chain lists the client first and each proxy after it. Walk from the
		// right and take the first hop that is not one of our proxies: anything
		// to its left was written by the client and cannot be trusted.
		$hops = array_reverse( array_map( 'trim', explode( ',', (string) $_SERVER[ $key ] ) ) );

		foreach ( $hops as $hop ) {
			if ( ! filter_var( $hop, FILTER_VALIDATE_IP ) ) {
				return $remote;
			}
			if ( ! self::is_trusted_proxy( $hop ) ) {
				return $hop;
			}
		}

		return $remote;
	}

	/**
	 * @param string $ip
	 * @return bool
	 */
	private static function is_trusted_proxy( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( ! self::$trusted ) {
			return self::is_private( $ip );
		}
		foreach ( self::$trusted as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the current request looks like it came through an unconfigured
	 * proxy: a private/loopback REMOTE_ADDR carrying a forwarding header.
	 *
	 * @return bool
	 */
	public static function proxy_suspected() {
		return 'none' === self::$header && self::looks_proxied();
	}

	/**
	 * The raw signal, regardless of configuration.
	 *
	 * @return bool
	 */
	public static function looks_proxied() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		if ( ! self::is_private( $remote ) ) {
			return false;
		}
		foreach ( self::FORWARDING_HEADERS as $key ) {
			if ( ! empty( $_SERVER[ $key ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Private, loopback, link-local or unique-local.
	 *
	 * @param string $ip
	 * @return bool
	 */
	public static function is_private( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		return ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether an address falls in a single address or CIDR range. IPv4 and IPv6.
	 *
	 * @param string $ip
	 * @param string $range '203.0.113.7', '203.0.113.0/24', '2001:db8::/32'
	 * @return bool
	 */
	public static function in_range( $ip, $range ) {
		$range = trim( $range );
		if ( false === strpos( $range, '/' ) ) {
			$a = @inet_pton( $ip );
			$b = @inet_pton( $range );

			return false !== $a && $a === $b;
		}

		[ $subnet, $bits ] = explode( '/', $range, 2 );
		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bits = (int) $bits;
		$max  = strlen( $ip_bin ) * 8;
		if ( $bits < 0 || $bits > $max ) {
			return false;
		}

		$bytes = intdiv( $bits, 8 );
		if ( substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
			return false;
		}

		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $rest ) ) & 0xFF );

		return ( $ip_bin[ $bytes ] & $mask ) === ( $subnet_bin[ $bytes ] & $mask );
	}

	/**
	 * Parse a textarea of addresses / ranges (one per line, `#` comments allowed).
	 *
	 * @param string $text
	 * @return array{valid: string[], invalid: string[]}
	 */
	public static function parse_list( $text ) {
		$valid   = [];
		$invalid = [];

		foreach ( preg_split( '/[\r\n,]+/', (string) $text ) as $line ) {
			$line = trim( preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			if ( self::is_valid_range( $line ) ) {
				$valid[] = $line;
			} else {
				$invalid[] = $line;
			}
		}

		return [ 'valid' => array_values( array_unique( $valid ) ), 'invalid' => $invalid ];
	}

	/**
	 * @param string $range
	 * @return bool
	 */
	public static function is_valid_range( $range ) {
		if ( false === strpos( $range, '/' ) ) {
			return (bool) filter_var( $range, FILTER_VALIDATE_IP );
		}
		[ $subnet, $bits ] = explode( '/', $range, 2 );
		if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) || ! ctype_digit( $bits ) ) {
			return false;
		}

		return (int) $bits <= ( false === strpos( $subnet, ':' ) ? 32 : 128 );
	}

	/**
	 * Whether an address is on a list of addresses / ranges.
	 *
	 * @param string   $ip
	 * @param string[] $list
	 * @return bool
	 */
	public static function on_list( $ip, array $list ) {
		foreach ( $list as $range ) {
			if ( self::in_range( $ip, $range ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Salted hash of an address — what counters are keyed by, so no raw
	 * address is stored at rest.
	 *
	 * @param string $ip
	 * @return string
	 */
	public static function hash( $ip ) {
		return substr( hash_hmac( 'sha256', 'upw-sec|' . $ip, wp_salt( 'nonce' ) ), 0, 32 );
	}

	/**
	 * An address with its host part hidden, for display: 203.0.113.x / 2001:db8:1::x.
	 *
	 * @param string $ip
	 * @return string
	 */
	public static function mask( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return preg_replace( '/\.\d+$/', '.x', $ip );
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			// First 48 bits of the fully expanded form, so ::1 reads 0:0:0::x.
			$groups = array_slice( str_split( bin2hex( inet_pton( $ip ) ), 4 ), 0, 3 );

			return implode( ':', array_map( static fn( $g ) => ltrim( $g, '0' ) ?: '0', $groups ) ) . '::x';
		}

		return '?';
	}

	/**
	 * Turn a header name (`X-Visitor-IP`) into its $_SERVER key.
	 *
	 * @param string $name
	 * @return string
	 */
	public static function server_key( $name ) {
		$name = trim( $name );
		if ( '' === $name || ! preg_match( '/^[A-Za-z0-9-]+$/', $name ) ) {
			return '';
		}

		return 'HTTP_' . strtoupper( str_replace( '-', '_', $name ) );
	}
}

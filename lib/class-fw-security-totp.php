<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Time-based one-time passwords (RFC 6238, the scheme authenticator apps use):
 * HMAC-SHA1, 30-second steps, 6 digits. Pure functions — no WordPress state —
 * so the contracts test can check them against the RFC test vectors.
 */
class FW_Security_TOTP {

	const STEP   = 30;
	const DIGITS = 6;
	const B32    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * A new random secret: 20 bytes (160 bits, the RFC's recommendation), base32.
	 *
	 * @return string
	 */
	public static function new_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * The code for a given time step.
	 *
	 * @param string $key_binary raw key bytes
	 * @param int    $counter    time step
	 * @param int    $digits
	 * @param string $algo       'sha1' (default) | 'sha256' | 'sha512'
	 * @return string zero-padded code
	 */
	public static function hotp( $key_binary, $counter, $digits = self::DIGITS, $algo = 'sha1' ) {
		$msg  = pack( 'J', (int) $counter ); // 64-bit big-endian
		$hash = hash_hmac( $algo, $msg, $key_binary, true );

		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$bin    = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		return str_pad( (string) ( $bin % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * @param int $time unix seconds
	 * @return int
	 */
	public static function step( $time ) {
		return intdiv( (int) $time, self::STEP );
	}

	/**
	 * Check a code, allowing ±$drift steps for clock skew. Returns the matching
	 * step so the caller can refuse a replay of the same (or an older) step.
	 *
	 * @param string $secret_b32
	 * @param string $code
	 * @param int    $time
	 * @param int    $drift
	 * @return int|false matching step, or false
	 */
	public static function verify( $secret_b32, $code, $time, $drift = 1 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{' . self::DIGITS . '}$/', $code ) ) {
			return false;
		}
		$key = self::base32_decode( $secret_b32 );
		if ( '' === $key ) {
			return false;
		}
		$now = self::step( $time );
		for ( $i = -$drift; $i <= $drift; $i++ ) {
			if ( hash_equals( self::hotp( $key, $now + $i ), $code ) ) {
				return $now + $i;
			}
		}

		return false;
	}

	/**
	 * @param string $bin
	 * @return string
	 */
	public static function base32_encode( $bin ) {
		$bits = '';
		foreach ( str_split( $bin ) as $c ) {
			$bits .= str_pad( decbin( ord( $c ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0' ) ) ];
		}

		return $out;
	}

	/**
	 * Lenient decode: ignores case, spaces, hyphens and padding. Returns '' on
	 * any character outside the alphabet.
	 *
	 * @param string $b32
	 * @return string
	 */
	public static function base32_decode( $b32 ) {
		$b32 = strtoupper( preg_replace( '/[\s=-]+/', '', (string) $b32 ) );
		if ( '' === $b32 || strspn( $b32, self::B32 ) !== strlen( $b32 ) ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $b32 ) as $c ) {
			$bits .= str_pad( decbin( strpos( self::B32, $c ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}

		return $out;
	}

	/**
	 * The otpauth:// URI an authenticator app reads from the QR code.
	 *
	 * @param string $secret_b32
	 * @param string $account
	 * @param string $issuer
	 * @return string
	 */
	public static function uri( $secret_b32, $account, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		return 'otpauth://totp/' . $label . '?' . http_build_query( [
			'secret'    => $secret_b32,
			'issuer'    => $issuer,
			'algorithm' => 'SHA1',
			'digits'    => self::DIGITS,
			'period'    => self::STEP,
		], '', '&', PHP_QUERY_RFC3986 );
	}
}

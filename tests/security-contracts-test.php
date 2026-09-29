<?php
/**
 * Security extension contracts — the pure parts that fail silently if they
 * drift: one-time codes, address matching, cooldown arithmetic, slug rules and
 * login-URL rewriting.
 *
 *   php wp-cli.phar --path=<site> eval-file <plugin>/framework/extensions/security/tests/security-contracts-test.php
 *
 * Exit 0 = all pass, 1 = something regressed.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

$dir = dirname( __DIR__ ) . '/lib/';
foreach ( [ 'ip', 'throttle', 'totp', 'slug-rules', 'login-url' ] as $f ) {
	require_once $dir . 'class-fw-security-' . $f . '.php';
}

$fails = 0;
$count = 0;
$check = static function ( $label, $got, $want ) use ( &$fails, &$count ) {
	++$count;
	if ( $got !== $want ) {
		++$fails;
		echo "FAIL  $label\n      got:  " . var_export( $got, true ) . "\n      want: " . var_export( $want, true ) . "\n";
	}
};

// --- RFC 4226 HOTP vectors (6 digits, key "12345678901234567890").
$key  = '12345678901234567890';
$hotp = [ '755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489' ];
foreach ( $hotp as $counter => $want ) {
	$check( "hotp counter $counter", FW_Security_TOTP::hotp( $key, $counter, 6 ), $want );
}

// --- RFC 6238 TOTP vectors (SHA1, 8 digits).
$totp = [ 59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471', 1234567890 => '89005924', 2000000000 => '69279037', 20000000000 => '65353130' ];
foreach ( $totp as $t => $want ) {
	$check( "totp t=$t", FW_Security_TOTP::hotp( $key, FW_Security_TOTP::step( $t ), 8 ), $want );
}

// --- base32 (RFC 4648 vectors, unpadded) and round trip.
foreach ( [ '' => '', 'f' => 'MY', 'fo' => 'MZXQ', 'foo' => 'MZXW6', 'foob' => 'MZXW6YQ', 'fooba' => 'MZXW6YTB', 'foobar' => 'MZXW6YTBOI' ] as $in => $want ) {
	$check( "base32 '$in'", FW_Security_TOTP::base32_encode( $in ), $want );
}
$bin = random_bytes( 20 );
$check( 'base32 round trip', FW_Security_TOTP::base32_decode( FW_Security_TOTP::base32_encode( $bin ) ), $bin );
$check( 'base32 lenient decode', FW_Security_TOTP::base32_decode( 'mzxw 6ytb-oi==' ), 'foobar' );
$check( 'base32 rejects bad char', FW_Security_TOTP::base32_decode( 'MZXW1' ), '' );

// --- verify(): drift window and the step it returns.
$secret = FW_Security_TOTP::base32_encode( $key );
$now    = 1111111111;
$code   = FW_Security_TOTP::hotp( $key, FW_Security_TOTP::step( $now ) );
$check( 'verify current step', FW_Security_TOTP::verify( $secret, $code, $now ), FW_Security_TOTP::step( $now ) );
$check( 'verify one step late', FW_Security_TOTP::verify( $secret, $code, $now + 30 ), FW_Security_TOTP::step( $now ) );
$check( 'verify two steps late fails', FW_Security_TOTP::verify( $secret, $code, $now + 60 ), false );
$check( 'verify accepts spaces', FW_Security_TOTP::verify( $secret, substr( $code, 0, 3 ) . ' ' . substr( $code, 3 ), $now ), FW_Security_TOTP::step( $now ) );
$check( 'verify rejects letters', FW_Security_TOTP::verify( $secret, 'abcdef', $now ), false );

// --- Address ranges.
$ranges = [
	[ '203.0.113.7', '203.0.113.7', true ],
	[ '203.0.113.7', '203.0.113.8', false ],
	[ '203.0.113.7', '203.0.113.0/24', true ],
	[ '203.0.114.7', '203.0.113.0/24', false ],
	[ '10.1.2.3', '10.0.0.0/8', true ],
	[ '172.20.0.1', '172.16.0.0/12', true ],
	[ '172.32.0.1', '172.16.0.0/12', false ],
	[ '2001:db8::1', '2001:db8::/32', true ],
	[ '2001:db9::1', '2001:db8::/32', false ],
	[ '2001:db8::1', '203.0.113.0/24', false ],
	[ '203.0.113.7', '0.0.0.0/0', true ],
];
foreach ( $ranges as [ $ip, $range, $want ] ) {
	$check( "in_range $ip $range", FW_Security_IP::in_range( $ip, $range ), $want );
}
$parsed = FW_Security_IP::parse_list( "203.0.113.7\n# office\n10.0.0.0/8  # vpn\nnot-an-ip\n2001:db8::/129\n2001:db8::/48" );
$check( 'parse_list valid', $parsed['valid'], [ '203.0.113.7', '10.0.0.0/8', '2001:db8::/48' ] );
$check( 'parse_list invalid', $parsed['invalid'], [ 'not-an-ip', '2001:db8::/129' ] );
$check( 'is_private loopback', FW_Security_IP::is_private( '127.0.0.1' ), true );
$check( 'is_private public', FW_Security_IP::is_private( '203.0.113.7' ), false );
$check( 'mask v4', FW_Security_IP::mask( '203.0.113.7' ), '203.0.113.x' );
$check( 'mask v6', FW_Security_IP::mask( '2001:db8:1:2::7' ), '2001:db8:1::x' );
$check( 'mask v6 loopback', FW_Security_IP::mask( '::1' ), '0:0:0::x' );
$check( 'server_key', FW_Security_IP::server_key( 'X-Visitor-IP' ), 'HTTP_X_VISITOR_IP' );
$check( 'server_key rejects junk', FW_Security_IP::server_key( 'X Visitor' ), '' );

// --- Cooldown arithmetic: doubles, capped, never zero.
$base = 15 * 60;
$cap  = 12 * 3600;
$check( 'lock level 1', FW_Security_Throttle::lock_duration( 1, $base, $cap ), 900 );
$check( 'lock level 2', FW_Security_Throttle::lock_duration( 2, $base, $cap ), 1800 );
$check( 'lock level 5', FW_Security_Throttle::lock_duration( 5, $base, $cap ), 14400 );
$check( 'lock level 7 capped', FW_Security_Throttle::lock_duration( 7, $base, $cap ), $cap );
$check( 'lock level 500 capped', FW_Security_Throttle::lock_duration( 500, $base, $cap ), $cap );
$check( 'lock level 0 treated as 1', FW_Security_Throttle::lock_duration( 0, $base, $cap ), 900 );

// --- Slug format rules.
$slugs = [
	'team-entry' => true, 'abcd' => true, 'a1b2' => true, 'abc' => false, 'Team' => false, '-abc' => false,
	'abc-' => false, 'ab_cd' => false, 'wp-admin' => false, 'login' => false, 'admin' => false, 'feed' => false,
	str_repeat( 'a', 50 ) => true, str_repeat( 'a', 51 ) => false, 'my/path' => false,
];
foreach ( $slugs as $slug => $ok ) {
	$check( "slug format '$slug'", [] === FW_Security_Slug_Rules::errors( $slug, true ), $ok );
}

// --- Login URL rewriting (slug injected directly; init() is not run here).
$prop = new ReflectionProperty( 'FW_Security_Login_Url', 'slug' );
$prop->setAccessible( true );
$prop->setValue( null, 'team-entry' );
$home = home_url( '/team-entry' );
$urls = [
	site_url( 'wp-login.php' )                                  => $home,
	site_url( 'wp-login.php?action=lostpassword' )              => $home . '?action=lostpassword',
	'wp-login.php?checkemail=confirm'                           => $home . '?checkemail=confirm',
	site_url( 'wp-login.php?action=postpass' )                  => site_url( 'wp-login.php?action=postpass' ),
	site_url( 'wp-login.php?redirect_to=x&action=postpass' )    => site_url( 'wp-login.php?redirect_to=x&action=postpass' ),
	site_url( 'wp-admin/' )                                     => site_url( 'wp-admin/' ),
	site_url( 'not-wp-login.php' )                              => site_url( 'not-wp-login.php' ),
];
foreach ( $urls as $in => $want ) {
	$check( "url $in", FW_Security_Login_Url::_filter_url( $in ), $want );
}
$prop->setValue( null, '' );

echo ( $fails ? "\n$fails of $count checks FAILED\n" : "All $count security contract checks passed.\n" );
exit( $fails ? 1 : 0 );

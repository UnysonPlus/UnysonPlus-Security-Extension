<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

$manifest = [];

$manifest['name']        = __( 'Security', 'fw' );
$manifest['slug']        = 'unysonplus-security';
$manifest['description'] = __(
	'Login throttling, two-factor sign-in, XML-RPC and header hardening, a custom login address, and security checks in Site Health. Every measure that changes behaviour is off until you switch it on, and each one says what it does not protect against.',
	'fw'
);

$manifest['thumbnail']   = 'thumbnail.svg';

$manifest['version']     = '1.0.4';
$manifest['display']     = true;
$manifest['standalone']  = true;

// Repository Info
$manifest['github_update'] = 'UnysonPlus/UnysonPlus-Security-Extension';
$manifest['github_repo']   = 'https://github.com/UnysonPlus/UnysonPlus-Security-Extension';
$manifest['github_branch'] = 'main';

// Author Info
$manifest['author']     = 'UnysonPlus';
$manifest['author_uri'] = 'https://www.lastimosa.com.ph/unysonplus';

// Meta
$manifest['license']      = 'GPL-2.0-or-later';
$manifest['text_domain']  = 'fw';
$manifest['requires_php'] = '8.0';
$manifest['requires_wp']  = '6.2';

/**
 * Changelog
 * -----------------------------------------------------------------------------
 * 1.0.4 - Initial release. A security extension built on one rule: ship only
 *         measures that stop a named attack or report configuration the plugin
 *         cannot enforce, and say in each option what it does NOT protect
 *         against. Off by default and never seeded; after activation only
 *         read-only checks run. Measures, each its own switch: login
 *         throttling per address and address+username with doubling, capped
 *         cooldowns (wp-login.php, XML-RPC and REST application-password
 *         sign-ins), generic login errors, TOTP two-factor sign-in with
 *         single-use recovery codes (QR drawn in the browser; optional
 *         encryption via UPW_SECURITY_2FA_KEY), XML-RPC pingbacks-off or block,
 *         front-end framing / nosniff / referrer / HSTS headers with an HSTS
 *         wind-down, anonymous user-listing limits, an emergency log-everyone-
 *         out, and a stateless custom login address validated at save and
 *         proven by a loopback request before it is kept. Checks are added to
 *         Site Health (file editor, salts, public debug log, directory listing,
 *         headers actually served, proxy detection and more). Recovery never
 *         needs the admin screen: UPW_SECURITY_SAFE_MODE,
 *         UPW_SECURITY_LOGIN_SLUG, and wp upw-security commands; deactivating
 *         the extension restores stock WordPress immediately.
 */

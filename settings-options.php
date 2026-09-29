<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Security settings. Rendered on the extension's own page (Unyson+ → Security),
 * one native nav-tab per top-level `tab`, each holding box → group.
 *
 * Every description states what the measure does NOT do. That is deliberate:
 * a switch that implies more protection than it gives is how the measures
 * that matter get skipped.
 */

$minutes = static function ( array $values ) {
	$out = [];
	foreach ( $values as $m ) {
		/* translators: %d: minutes */
		$out[ (string) $m ] = $m >= 60 ? sprintf( _n( '%d hour', '%d hours', $m / 60, 'fw' ), $m / 60 ) : sprintf( _n( '%d minute', '%d minutes', $m, 'fw' ), $m );
	}

	return $out;
};

$hsts = [];
foreach ( FW_Security_Headers::hsts_choices() as $secs => $label ) {
	$hsts[ (string) $secs ] = $label;
}

$slug_locked = defined( 'UPW_SECURITY_LOGIN_SLUG' );
$two_fa_key  = FW_Security_Two_Factor::has_key();

$options = [
	'tab_login' => [
		'title'   => __( 'Login', 'fw' ),
		'type'    => 'tab',
		'options' => [
			'throttle_box' => [
				'title'   => __( 'Login throttling', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_throttle' => [
						'type'    => 'group',
						'options' => [
							'throttle_enabled'     => [
								'label' => __( 'Throttle failed sign-ins', 'fw' ),
								'desc'  => __( 'After too many wrong passwords from one address, that address waits before it may try again. Covers the login page, XML-RPC and application-password sign-ins. It slows guessing from one place; it does not stop slow guessing spread across many addresses — two-factor sign-in does. Limits count per address and per address + username, never per username alone, so nobody can lock you out of your own account by guessing badly on purpose.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
							'throttle_attempts'    => [
								'label'   => __( 'Attempts allowed', 'fw' ),
								'desc'    => __( 'Wrong passwords for one username from one address before a cooldown. One address trying many usernames cools down after four times this many.', 'fw' ),
								'type'    => 'select',
								'value'   => '5',
								'choices' => [ '3' => '3', '5' => '5', '10' => '10', '20' => '20' ],
							],
							'throttle_window'      => [
								'label'   => __( 'Counted over', 'fw' ),
								'type'    => 'select',
								'value'   => '15',
								'choices' => $minutes( [ 5, 15, 30, 60 ] ),
							],
							'throttle_lockout'     => [
								'label'   => __( 'First cooldown', 'fw' ),
								'desc'    => __( 'Each repeat within a day doubles it, up to the maximum. Cooldowns are never permanent.', 'fw' ),
								'type'    => 'select',
								'value'   => '15',
								'choices' => $minutes( [ 5, 15, 30, 60 ] ),
							],
							'throttle_lockout_max' => [
								'label'   => __( 'Longest cooldown', 'fw' ),
								'type'    => 'select',
								'value'   => '12',
								'choices' => [ '1' => __( '1 hour', 'fw' ), '6' => __( '6 hours', 'fw' ), '12' => __( '12 hours', 'fw' ), '24' => __( '24 hours', 'fw' ) ],
							],
							'throttle_allowlist'   => [
								'label' => __( 'Never throttle', 'fw' ),
								'desc'  => __( 'Addresses or ranges that are never throttled, one per line (203.0.113.7, 203.0.113.0/24, 2001:db8::/32). Useful for an office address shared by many people.', 'fw' ),
								'type'  => 'textarea',
								'value' => '',
							],
						],
					],
				],
			],
			'proxy_box'    => [
				'title'   => __( 'Visitor addresses behind a proxy or CDN', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_proxy' => [
						'type'    => 'group',
						'options' => [
							'proxy_header'        => [
								'label'   => __( 'Real visitor address comes from', 'fw' ),
								'desc'    => __( 'Leave on “Connection address” unless the site sits behind a proxy or CDN. Behind one, every visitor otherwise appears as the proxy, and throttling would lock everyone out together. A header is only believed when the request comes from a trusted proxy — anyone can send one.', 'fw' ),
								'type'    => 'select',
								'value'   => 'none',
								'choices' => [
									'none'            => __( 'Connection address (no proxy)', 'fw' ),
									'x-forwarded-for' => 'X-Forwarded-For',
									'x-real-ip'       => 'X-Real-IP',
									'custom'          => __( 'Another header (below)', 'fw' ),
								],
							],
							'proxy_header_custom' => [
								'label' => __( 'Header name', 'fw' ),
								'desc'  => __( 'Only for “Another header”, e.g. X-Visitor-IP.', 'fw' ),
								'type'  => 'text',
								'value' => '',
							],
							'proxy_trusted'       => [
								'label' => __( 'Trusted proxy addresses', 'fw' ),
								'desc'  => __( 'Addresses or ranges your proxy connects from, one per line. Leave empty to trust only private-network proxies (10.x, 172.16–31.x, 192.168.x, loopback).', 'fw' ),
								'type'  => 'textarea',
								'value' => '',
							],
						],
					],
				],
			],
			'errors_box'   => [
				'title'   => __( 'Login error messages', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_errors' => [
						'type'    => 'group',
						'options' => [
							'generic_login_errors' => [
								'label' => __( 'One message for any wrong sign-in', 'fw' ),
								'desc'  => __( 'WordPress says whether the username or the password was wrong, which confirms that an account exists. This shows one message for both. It closes one path only: the lost-password form, author pages and the REST API can still reveal usernames.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
						],
					],
				],
			],
		],
	],

	'tab_two_factor' => [
		'title'   => __( 'Two-factor', 'fw' ),
		'type'    => 'tab',
		'options' => [
			'twofa_box' => [
				'title'   => __( 'Two-factor sign-in', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_twofa' => [
						'type'    => 'group',
						'options' => [
							'twofa_enabled' => [
								'label' => __( 'Offer two-factor sign-in', 'fw' ),
								'desc'  => ( $two_fa_key
									? __( 'Secrets are encrypted with UPW_SECURITY_2FA_KEY from wp-config.php.', 'fw' )
									: __( 'Secrets are stored unencrypted in the database. Define UPW_SECURITY_2FA_KEY (32+ random characters) in wp-config.php before anyone enrols to encrypt them; changing or removing it later makes existing enrolments need a recovery code.', 'fw' ) )
									. ' '
									. __( 'After the password, users who set it up enter a 6-digit code from an authenticator app on their phone. Each user turns it on from their own profile, where they also get single-use recovery codes. It defeats leaked, reused and guessed passwords. It does not protect a session that is already signed in, and application passwords (for programs) are not asked for a code. Switching this off keeps every enrolment and simply stops asking.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
						],
					],
				],
			],
		],
	],

	'tab_hardening' => [
		'title'   => __( 'Hardening', 'fw' ),
		'type'    => 'tab',
		'options' => [
			'xmlrpc_box'  => [
				'title'   => __( 'XML-RPC', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_xmlrpc' => [
						'type'    => 'group',
						'options' => [
							'xmlrpc_mode' => [
								'label'   => __( 'XML-RPC', 'fw' ),
								'desc'    => __( 'Pingbacks let anyone make your site send requests to other addresses — used in reflection floods. “Pingbacks off” removes them and keeps the rest of XML-RPC. “Block” refuses every XML-RPC request; remote-publishing tools and older mobile apps that use it will stop working. Neither is a brute-force fix: WordPress already limits XML-RPC password guessing, and throttling covers the rest.', 'fw' ),
								'type'    => 'select',
								'value'   => 'leave',
								'choices' => [
									'leave'     => __( 'Leave as WordPress sets it', 'fw' ),
									'pingbacks' => __( 'Pingbacks off', 'fw' ),
									'block'     => __( 'Block XML-RPC entirely', 'fw' ),
								],
							],
						],
					],
				],
			],
			'headers_box' => [
				'title'   => __( 'Security headers (front end)', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_headers' => [
						'type'    => 'group',
						'options' => [
							'hdr_frame'       => [
								'label' => __( 'Refuse framing by other sites', 'fw' ),
								'desc'  => __( 'Stops other sites showing your pages inside a frame to trick visitors into clicking (clickjacking). Your own previews and editors keep working. Breaks deliberate embedding of your pages on another site.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
							'hdr_nosniff'     => [
								'label' => __( 'No content-type guessing', 'fw' ),
								'desc'  => __( 'Browsers treat each file strictly as the type the server says, so an uploaded file cannot be run as a script by being guessed as one.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
							'hdr_referrer'    => [
								'label'   => __( 'Referrer policy', 'fw' ),
								'desc'    => __( 'How much of a page’s address is passed to the sites your visitors click through to. The recommended setting sends only your domain to other sites.', 'fw' ),
								'type'    => 'select',
								'value'   => 'off',
								'choices' => [
									'off'                             => __( 'Browser default (no header)', 'fw' ),
									'strict-origin-when-cross-origin' => __( 'Domain only to other sites (recommended)', 'fw' ),
									'same-origin'                     => __( 'Nothing to other sites', 'fw' ),
									'strict-origin'                   => __( 'Domain only, everywhere', 'fw' ),
									'no-referrer'                     => __( 'Nothing, anywhere', 'fw' ),
								],
							],
							'hdr_hsts'        => [
								'label' => __( 'Always use HTTPS (HSTS)', 'fw' ),
								'desc'  => __( 'Browsers that have visited once refuse plain HTTP to this site afterwards, which stops a network in between downgrading the connection. Careful: if HTTPS ever stops working, returning visitors cannot reach the site until the time below runs out. Start with 1 day. Turning it off sends browsers a “forget it” instruction for as long as the old duration.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
							'hsts_max_age'    => [
								'label'   => __( 'HSTS duration', 'fw' ),
								'type'    => 'select',
								'value'   => (string) DAY_IN_SECONDS,
								'choices' => $hsts,
							],
							'hsts_subdomains' => [
								'label' => __( 'Include subdomains', 'fw' ),
								'desc'  => __( 'Only if every subdomain of this domain works over HTTPS.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
						],
					],
				],
			],
			'listing_box' => [
				'title'   => __( 'User listing', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_listing' => [
						'type'    => 'group',
						'options' => [
							'limit_user_listing' => [
								'label' => __( 'Hide the user list from visitors', 'fw' ),
								'desc'  => __( 'Noise reduction, not protection. Stops logged-out visitors listing usernames through the REST API, ?author=N links and embed data. Usernames are not secrets — bylines and author pages still show them — so this only slows automated tools. Sites that read the user list without signing in (a separate front end, for example) will lose it.', 'fw' ),
								'type'  => 'switch',
								'value' => false,
							],
						],
					],
				],
			],
		],
	],

	'tab_login_url' => [
		'title'   => __( 'Login address', 'fw' ),
		'type'    => 'tab',
		'options' => [
			'login_url_box' => [
				'title'   => __( 'Custom login address', 'fw' ),
				'type'    => 'box',
				'options' => [
					'group_login_url' => [
						'type'    => 'group',
						'options' => [
							'login_slug' => [
								'label' => __( 'Login address', 'fw' ),
								'desc'  => ( $slug_locked
									? __( 'Set by UPW_SECURITY_LOGIN_SLUG in wp-config.php; this field is ignored while that line is there.', 'fw' ) . ' '
									: '' )
									. sprintf(
										/* translators: %s: example URL */
										__( 'Leave empty for the standard wp-login.php. Enter a name to move the login page to %s. This reduces automated login attempts and log noise. It does not hide your site from a determined attacker: the REST API, admin-ajax and XML-RPC stay reachable, and any login link on your site reveals the new address. Use throttling and two-factor sign-in for protection. If you lose the address: it is emailed to the site admin address when saved; add define( \'UPW_SECURITY_LOGIN_SLUG\', false ); to wp-config.php; or run wp upw-security login-url reset. Deactivating this extension restores wp-login.php immediately.', 'fw' ),
										esc_html( home_url( '/your-name' ) )
									),
								'type'  => 'text',
								'value' => '',
								'attr'  => $slug_locked ? [ 'disabled' => 'disabled' ] : [],
							],
						],
					],
				],
			],
		],
	],
];

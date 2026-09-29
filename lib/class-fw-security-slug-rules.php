<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}

/**
 * Validation for a custom login slug — run at save time, so a bad slug fails
 * loudly on the settings screen instead of at the next login.
 *
 * The definitive test is the same one WordPress itself would apply: take the
 * first rewrite rule that matches the path and ask whether the query it
 * produces resolves to anything real. That covers pages, posts, attachments,
 * terms, archives and feeds without keeping a list of each.
 */
class FW_Security_Slug_Rules {

	/** Names refused outright: WordPress paths, and the first guesses a bot tries. */
	const RESERVED = [
		'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login', 'wp-login-php', 'wp-signup', 'wp-activate',
		'wp-cron', 'wp-sitemap', 'xmlrpc', 'login', 'log-in', 'signin', 'sign-in', 'admin', 'administrator',
		'dashboard', 'backend', 'user', 'users', 'account', 'my-account', 'register', 'feed', 'rss', 'rss2',
		'atom', 'rdf', 'embed', 'trackback', 'comments', 'comment-page', 'page', 'search', 'author', 'sitemap',
		'robots-txt', 'favicon-ico', 'index-php', 'category', 'tag', 'type', 'attachment',
	];

	/**
	 * Every reason the slug cannot be used. Empty array = valid.
	 *
	 * @param string $slug
	 * @param bool   $format_only Skip the site lookups (used by the contracts test).
	 * @return string[]
	 */
	public static function errors( $slug, $format_only = false ) {
		$slug   = (string) $slug;
		$errors = [];

		if ( ! preg_match( '/^[a-z0-9][a-z0-9-]{2,48}[a-z0-9]$/', $slug ) ) {
			return [ __( 'Use 4 to 50 lowercase letters, digits and hyphens, not starting or ending with a hyphen.', 'fw' ) ];
		}
		if ( in_array( $slug, self::RESERVED, true ) ) {
			return [ __( 'That name is reserved by WordPress, or is one of the first addresses automated tools try.', 'fw' ) ];
		}
		if ( $format_only ) {
			return [];
		}

		if ( is_multisite() ) {
			$errors[] = __( 'A custom login address is not supported on a multisite network yet.', 'fw' );
		}
		if ( '' === (string) get_option( 'permalink_structure' ) ) {
			$errors[] = __( 'Permalinks are set to Plain. With plain permalinks the web server never passes a custom address to WordPress, so it would not work. Choose any other permalink structure first (Settings → Permalinks).', 'fw' );
		}

		global $wp;
		if ( $wp instanceof WP && in_array( $slug, (array) $wp->public_query_vars, true ) ) {
			$errors[] = __( 'That name is a WordPress query variable.', 'fw' );
		}

		foreach ( self::rewrite_bases() as $base => $what ) {
			if ( $base === $slug ) {
				/* translators: %s: e.g. "the Products post type" */
				$errors[] = sprintf( __( 'That name is already the address base of %s.', 'fw' ), $what );
			}
		}

		$content = self::content_using( $slug );
		if ( $content ) {
			/* translators: %s: title of the post or page that already uses the address */
			$errors[] = sprintf( __( 'That address is already used by “%s” (any status, including drafts and trash).', 'fw' ), $content );
		}

		$resolved = self::resolves( $slug );
		if ( '' !== $resolved && ! $content ) {
			/* translators: %s: a description such as "a category" */
			$errors[] = sprintf( __( 'That address already opens %s on this site.', 'fw' ), $resolved );
		}

		if ( file_exists( ABSPATH . $slug ) ) {
			$errors[] = __( 'A file or folder with that name exists in the WordPress directory.', 'fw' );
		}

		return $errors;
	}

	/**
	 * @return array<string, string> rewrite base => description
	 */
	private static function rewrite_bases() {
		$bases = [];
		foreach ( get_post_types( [], 'objects' ) as $pt ) {
			if ( is_array( $pt->rewrite ) && ! empty( $pt->rewrite['slug'] ) ) {
				/* translators: %s: post type label */
				$bases[ trim( $pt->rewrite['slug'], '/' ) ] = sprintf( __( 'the %s post type', 'fw' ), $pt->label );
			}
			if ( is_string( $pt->has_archive ) && '' !== $pt->has_archive ) {
				/* translators: %s: post type label */
				$bases[ trim( $pt->has_archive, '/' ) ] = sprintf( __( 'the %s archive', 'fw' ), $pt->label );
			}
		}
		foreach ( get_taxonomies( [], 'objects' ) as $tax ) {
			if ( is_array( $tax->rewrite ) && ! empty( $tax->rewrite['slug'] ) ) {
				/* translators: %s: taxonomy label */
				$bases[ trim( $tax->rewrite['slug'], '/' ) ] = sprintf( __( 'the %s taxonomy', 'fw' ), $tax->label );
			}
		}

		return $bases;
	}

	/**
	 * A post of any type and status (except auto-drafts) whose slug is the name.
	 *
	 * @param string $slug
	 * @return string title, or ''
	 */
	private static function content_using( $slug ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT ID, post_title FROM {$wpdb->posts} WHERE post_name IN (%s, %s) AND post_status <> 'auto-draft' LIMIT 1",
			$slug,
			$slug . '__trashed'
		) );

		return $row ? ( '' !== $row->post_title ? $row->post_title : '#' . $row->ID ) : '';
	}

	/**
	 * Whether the path already resolves through the rewrite rules, the way
	 * WP::parse_request() would: first matching rule wins.
	 *
	 * @param string $slug
	 * @return string description of what it opens, or ''
	 */
	public static function resolves( $slug ) {
		global $wp_rewrite;
		$rules = $wp_rewrite instanceof WP_Rewrite ? $wp_rewrite->wp_rewrite_rules() : [];
		if ( ! $rules ) {
			return '';
		}

		foreach ( [ $slug, $slug . '/' ] as $path ) {
			foreach ( $rules as $regex => $query ) {
				if ( ! preg_match( "#^$regex#", $path, $matches ) ) {
					continue;
				}
				$query = preg_replace( '!^.+\?!', '', $query );
				parse_str( WP_MatchesMapRegex::apply( $query, $matches ), $vars );

				return self::describe_if_real( $vars );
			}
		}

		return '';
	}

	/**
	 * @param array $vars query vars a rule produced
	 * @return string
	 */
	private static function describe_if_real( array $vars ) {
		foreach ( [ 'pagename', 'name', 'attachment', 'p', 'page_id' ] as $key ) {
			if ( ! empty( $vars[ $key ] ) ) {
				$q = new WP_Query( [
					'post_type'      => 'any',
					'post_status'    => [ 'publish', 'future', 'draft', 'pending', 'private', 'inherit', 'trash' ],
					'posts_per_page' => 1,
					'fields'         => 'ids',
					'no_found_rows'  => true,
				] + array_intersect_key( $vars, array_flip( [ 'pagename', 'name', 'attachment', 'p', 'page_id', 'post_type' ] ) ) );

				return $q->posts ? __( 'existing content', 'fw' ) : '';
			}
		}

		foreach ( get_taxonomies( [], 'objects' ) as $tax ) {
			if ( $tax->query_var && ! empty( $vars[ $tax->query_var ] ) ) {
				return term_exists( (string) $vars[ $tax->query_var ], $tax->name ) ? __( 'a category, tag or other term', 'fw' ) : '';
			}
		}
		if ( ! empty( $vars['category_name'] ) ) {
			return term_exists( (string) $vars['category_name'], 'category' ) ? __( 'a category', 'fw' ) : '';
		}

		// Any other rule — a feed, a date archive, a sitemap, a post-type archive —
		// is something WordPress serves at that path.
		return $vars ? __( 'a WordPress archive, feed or endpoint', 'fw' ) : '';
	}
}

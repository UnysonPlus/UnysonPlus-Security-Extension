<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}
/**
 * @var FW_Extension_Security $ext
 * @var array                 $tabs
 * @var array                 $values
 * @var array                 $flash
 * @var array                 $lockouts
 * @var array|false           $probe
 */
$safe = FW_Extension_Security::is_safe_mode();
?>
<div class="wrap fw-ext-security">
	<h1 class="wp-heading-inline"><?php esc_html_e( 'Security', 'fw' ); ?></h1>
	<p class="description upw-sec-lede">
		<?php esc_html_e( 'Each measure below is off until you switch it on, and each says what it does not protect against. Read-only checks run in Tools → Site Health.', 'fw' ); ?>
	</p>

	<?php if ( $safe ) : ?>
		<div class="notice notice-error inline"><p>
			<strong><?php esc_html_e( 'Safe mode is on.', 'fw' ); ?></strong>
			<?php esc_html_e( 'UPW_SECURITY_SAFE_MODE is set in wp-config.php, so none of the saved measures are running. You can still change settings; they take effect when the line is removed.', 'fw' ); ?>
		</p></div>
	<?php endif; ?>

	<?php foreach ( (array) $flash['errors'] as $msg ) : ?>
		<div class="notice notice-error is-dismissible"><p><?php echo esc_html( $msg ); ?></p></div>
	<?php endforeach; ?>
	<?php foreach ( (array) $flash['notes'] as $msg ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $msg ); ?></p></div>
	<?php endforeach; ?>
	<?php if ( isset( $_GET['fw-saved'] ) && ! $flash['errors'] && ! $flash['notes'] ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'fw' ); ?></p></div>
	<?php endif; ?>

	<h2 class="nav-tab-wrapper upw-sec-tabs">
		<a href="#status" class="nav-tab nav-tab-active" data-tab="status"><?php esc_html_e( 'Status', 'fw' ); ?></a>
		<?php foreach ( $tabs as $tab_id => $tab ) : ?>
			<a href="#<?php echo esc_attr( $tab_id ); ?>" class="nav-tab" data-tab="<?php echo esc_attr( $tab_id ); ?>"><?php echo esc_html( $tab['title'] ?? $tab_id ); ?></a>
		<?php endforeach; ?>
	</h2>

	<div class="upw-sec-panel is-active" id="panel-status">
		<div class="metabox-holder">
			<div class="postbox"><div class="postbox-header"><h2 class="hndle"><?php esc_html_e( 'Measures', 'fw' ); ?></h2></div>
				<div class="inside">
					<table class="widefat striped upw-sec-status">
						<thead><tr><th><?php esc_html_e( 'Measure', 'fw' ); ?></th><th><?php esc_html_e( 'State', 'fw' ); ?></th></tr></thead>
						<tbody>
						<?php
						$labels = [
							'throttle_enabled'     => __( 'Login throttling', 'fw' ),
							'generic_login_errors' => __( 'One message for any wrong sign-in', 'fw' ),
							'twofa_enabled'        => __( 'Two-factor sign-in', 'fw' ),
							'xmlrpc_mode'          => __( 'XML-RPC', 'fw' ),
							'hdr_frame'            => __( 'Header: refuse framing', 'fw' ),
							'hdr_nosniff'          => __( 'Header: no content-type guessing', 'fw' ),
							'hdr_referrer'         => __( 'Header: referrer policy', 'fw' ),
							'hdr_hsts'             => __( 'Header: HSTS', 'fw' ),
							'limit_user_listing'   => __( 'Hide the user list from visitors', 'fw' ),
							'login_slug'           => __( 'Custom login address', 'fw' ),
						];
						foreach ( $labels as $key => $label ) :
							$running = $ext->measure_running( $key );
							$detail  = '';
							if ( 'xmlrpc_mode' === $key ) {
								$detail = [ 'leave' => '', 'pingbacks' => __( 'pingbacks off', 'fw' ), 'block' => __( 'blocked', 'fw' ) ][ $values['xmlrpc_mode'] ] ?? '';
							} elseif ( 'login_slug' === $key && $running ) {
								$detail = home_url( '/' . $ext->login_slug() );
							} elseif ( 'hdr_referrer' === $key && $running ) {
								$detail = $values['hdr_referrer'];
							}
							?>
							<tr>
								<td><?php echo esc_html( $label ); ?></td>
								<td>
									<span class="upw-sec-pill <?php echo $running ? 'is-on' : 'is-off'; ?>"><?php echo $running ? esc_html__( 'On', 'fw' ) : esc_html__( 'Off', 'fw' ); ?></span>
									<?php if ( '' !== $detail ) : ?><code><?php echo esc_html( $detail ); ?></code><?php endif; ?>
									<?php if ( 'login_slug' === $key && defined( 'UPW_SECURITY_LOGIN_SLUG' ) ) : ?>
										<em><?php esc_html_e( '(set in wp-config.php)', 'fw' ); ?></em>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					<p><a href="<?php echo esc_url( admin_url( 'site-health.php' ) ); ?>"><?php esc_html_e( 'See the security checks in Site Health', 'fw' ); ?> &rarr;</a></p>
				</div>
			</div>

			<div class="postbox"><div class="postbox-header"><h2 class="hndle"><?php esc_html_e( 'Login lockouts', 'fw' ); ?></h2></div>
				<div class="inside">
					<?php if ( ! $lockouts ) : ?>
						<p><?php esc_html_e( 'No address is cooling down.', 'fw' ); ?></p>
					<?php else : ?>
						<table class="widefat striped">
							<thead><tr>
								<th><?php esc_html_e( 'Address', 'fw' ); ?></th>
								<th><?php esc_html_e( 'Username tried', 'fw' ); ?></th>
								<th><?php esc_html_e( 'Until', 'fw' ); ?></th>
								<th></th>
							</tr></thead>
							<tbody>
							<?php foreach ( $lockouts as $key => $l ) : ?>
								<tr>
									<td><code><?php echo esc_html( $l['label'] ); ?></code></td>
									<td><?php echo 'ip' === $l['scope'] ? '<em>' . esc_html__( 'any (many usernames)', 'fw' ) . '</em>' : esc_html( $l['user'] ); ?></td>
									<td><?php echo esc_html( wp_date( get_option( 'time_format' ), (int) $l['until'] ) ); ?></td>
									<td><a class="button button-small" href="<?php echo esc_url( FW_Extension_Security::action_url( 'unlock', [ 'key' => $key ] ) ); ?>"><?php esc_html_e( 'Unlock', 'fw' ); ?></a></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
						<p><a class="button" href="<?php echo esc_url( FW_Extension_Security::action_url( 'unlock_all' ) ); ?>"><?php esc_html_e( 'Unlock all', 'fw' ); ?></a></p>
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'Addresses are shown with the last part hidden; the full address is never stored.', 'fw' ); ?></p>
				</div>
			</div>

			<div class="postbox"><div class="postbox-header"><h2 class="hndle"><?php esc_html_e( 'Tools', 'fw' ); ?></h2></div>
				<div class="inside upw-sec-tools">
					<p>
						<a class="button upw-sec-confirm" href="<?php echo esc_url( FW_Extension_Security::action_url( 'logout_all' ) ); ?>"
							data-confirm="<?php esc_attr_e( 'Sign every user out, everywhere — including you? Everyone will need to sign in again. Passwords and application passwords are not changed.', 'fw' ); ?>"><?php esc_html_e( 'Log everyone out', 'fw' ); ?></a>
						<span class="description"><?php esc_html_e( 'After a suspected break-in: ends every signed-in session at once. Pair it with password resets — someone who has a password simply signs in again.', 'fw' ); ?></span>
					</p>
					<p>
						<a class="button" href="<?php echo esc_url( FW_Extension_Security::action_url( 'probe_uploads' ) ); ?>"><?php esc_html_e( 'Check whether PHP runs in uploads', 'fw' ); ?></a>
						<span class="description"><?php esc_html_e( 'Writes a harmless test file into the uploads folder, requests it and deletes it.', 'fw' ); ?></span>
						<?php if ( is_array( $probe ) ) : ?>
							<br><strong class="upw-sec-probe is-<?php echo esc_attr( $probe['status'] ); ?>"><?php echo esc_html( $probe['message'] ); ?></strong>
						<?php endif; ?>
					</p>
					<p>
						<a class="button button-link-delete upw-sec-confirm" href="<?php echo esc_url( FW_Extension_Security::action_url( 'purge' ) ); ?>"
							data-confirm="<?php esc_attr_e( 'Remove every Security setting, lockout and two-factor enrolment? Every measure goes back to off.', 'fw' ); ?>"><?php esc_html_e( 'Remove all security data', 'fw' ); ?></a>
					</p>
					<p class="description"><?php esc_html_e( 'Locked out? Add define( \'UPW_SECURITY_SAFE_MODE\', true ); to wp-config.php to switch every measure off, or use the wp upw-security commands (status, disable, unlock, 2fa reset, login-url reset).', 'fw' ); ?></p>
				</div>
			</div>
		</div>
	</div>

	<form method="post" action="" class="upw-sec-form">
		<?php wp_nonce_field( FW_Extension_Security::SETTINGS_NONCE ); ?>
		<input type="hidden" name="upw_tab" value="">
		<?php foreach ( $tabs as $tab_id => $tab ) : ?>
			<div class="upw-sec-panel" id="panel-<?php echo esc_attr( $tab_id ); ?>">
				<?php echo fw()->backend->render_options( is_array( $tab['options'] ?? null ) ? $tab['options'] : [], $values ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
				<p class="submit"><button type="submit" class="button button-primary"><?php esc_html_e( 'Save Changes', 'fw' ); ?></button></p>
			</div>
		<?php endforeach; ?>
	</form>
</div>

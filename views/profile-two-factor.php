<?php if ( ! defined( 'FW' ) ) {
	die( 'Forbidden' );
}
/**
 * @var WP_User $user
 * @var bool    $is_self
 * @var bool    $enrolled
 * @var int     $left
 * @var int     $since
 * @var bool    $readable
 * @var string  $nonce
 */
?>
<h2 id="upw-two-factor"><?php esc_html_e( 'Two-factor sign-in', 'fw' ); ?></h2>
<table class="form-table" role="presentation">
	<tr>
		<th scope="row"><?php esc_html_e( 'Authenticator app', 'fw' ); ?></th>
		<td>
			<div class="upw-2fa" data-user="<?php echo (int) $user->ID; ?>" data-nonce="<?php echo esc_attr( $nonce ); ?>">
				<?php if ( ! $is_self ) : ?>
					<?php if ( $enrolled ) : ?>
						<p><span class="upw-sec-pill is-on"><?php esc_html_e( 'On', 'fw' ); ?></span>
							<?php
							/* translators: %s: date */
							echo esc_html( sprintf( __( 'since %s', 'fw' ), wp_date( get_option( 'date_format' ), $since ) ) );
							?>
						</p>
						<p>
							<button type="button" class="button upw-2fa-reset"
								data-confirm="<?php esc_attr_e( 'Remove two-factor sign-in for this user? They will sign in with just their password until they set it up again.', 'fw' ); ?>"><?php esc_html_e( 'Reset two-factor sign-in', 'fw' ); ?></button>
						</p>
						<p class="description"><?php esc_html_e( 'For a user who has lost their phone and their recovery codes.', 'fw' ); ?></p>
					<?php else : ?>
						<p><span class="upw-sec-pill is-off"><?php esc_html_e( 'Off', 'fw' ); ?></span> <?php esc_html_e( 'Only the user can set it up, from their own profile.', 'fw' ); ?></p>
					<?php endif; ?>

				<?php elseif ( $enrolled ) : ?>
					<p><span class="upw-sec-pill is-on"><?php esc_html_e( 'On', 'fw' ); ?></span>
						<?php
						/* translators: 1: date, 2: number of codes */
						echo esc_html( sprintf( __( 'since %1$s · %2$d recovery codes left', 'fw' ), wp_date( get_option( 'date_format' ), $since ), $left ) );
						?>
					</p>
					<?php if ( ! $readable ) : ?>
						<p class="upw-2fa-warn"><?php esc_html_e( 'Your secret cannot be read with the current UPW_SECURITY_2FA_KEY, so codes from your app will not work. Sign in with a recovery code, then turn two-factor off and set it up again.', 'fw' ); ?></p>
					<?php endif; ?>
					<p>
						<label for="upw-2fa-current" class="screen-reader-text"><?php esc_html_e( 'Current code', 'fw' ); ?></label>
						<input type="text" id="upw-2fa-current" class="regular-text upw-2fa-current" autocomplete="one-time-code" placeholder="<?php esc_attr_e( 'Current code from your app', 'fw' ); ?>">
						<button type="button" class="button upw-2fa-codes"><?php esc_html_e( 'New recovery codes', 'fw' ); ?></button>
						<button type="button" class="button button-link-delete upw-2fa-disable"><?php esc_html_e( 'Turn off', 'fw' ); ?></button>
					</p>
					<p class="description"><?php esc_html_e( 'Both need a current code (or a recovery code), so someone using a session you left open cannot remove your second factor.', 'fw' ); ?></p>

				<?php else : ?>
					<p><?php esc_html_e( 'After your password, you will also enter a 6-digit code from an authenticator app on your phone. A leaked or guessed password is then not enough to sign in as you.', 'fw' ); ?></p>
					<p><button type="button" class="button button-primary upw-2fa-start"><?php esc_html_e( 'Set up two-factor sign-in', 'fw' ); ?></button></p>
					<div class="upw-2fa-setup" hidden>
						<ol>
							<li><?php esc_html_e( 'In your authenticator app, add an account and scan this code:', 'fw' ); ?>
								<div class="upw-2fa-qr" aria-hidden="true"></div>
								<?php esc_html_e( 'Can’t scan it? Enter this key instead:', 'fw' ); ?> <code class="upw-2fa-secret"></code>
							</li>
							<li>
								<label for="upw-2fa-confirm-code"><?php esc_html_e( 'Enter the 6-digit code the app shows:', 'fw' ); ?></label><br>
								<input type="text" id="upw-2fa-confirm-code" class="upw-2fa-confirm-code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" size="10">
								<button type="button" class="button button-primary upw-2fa-confirm"><?php esc_html_e( 'Confirm and turn on', 'fw' ); ?></button>
							</li>
						</ol>
						<p class="description"><?php esc_html_e( 'The code is drawn in your browser; the key never leaves this site.', 'fw' ); ?></p>
					</div>
				<?php endif; ?>

				<div class="upw-2fa-codes-out" hidden>
					<p><strong><?php esc_html_e( 'Your recovery codes — save them now. They are shown only once.', 'fw' ); ?></strong></p>
					<p><?php esc_html_e( 'Each works once, in place of an app code, if you lose your phone.', 'fw' ); ?></p>
					<pre class="upw-2fa-code-list"></pre>
					<p>
						<button type="button" class="button upw-2fa-copy"><?php esc_html_e( 'Copy', 'fw' ); ?></button>
						<button type="button" class="button upw-2fa-done"><?php esc_html_e( 'I have saved them', 'fw' ); ?></button>
					</p>
				</div>
				<p class="upw-2fa-msg" role="status" aria-live="polite"></p>
			</div>
		</td>
	</tr>
</table>

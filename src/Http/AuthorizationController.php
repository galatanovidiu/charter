<?php
/**
 * OAuth browser authorization controller.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use GalatanOvidiu\Charter\OAuth\AuthorizationRequest;
use GalatanOvidiu\Charter\OAuth\AuthorizationService;
use GalatanOvidiu\Charter\OAuth\ClientRegistry;
use GalatanOvidiu\Charter\OAuth\ProtocolException;
use GalatanOvidiu\Charter\Site\SiteState;

/**
 * Uses WordPress login and nonce protection for explicit user consent.
 *
 * @since 0.1.0
 */
final class AuthorizationController {

	private const PARAMETERS = array(
		'response_type',
		'client_id',
		'redirect_uri',
		'code_challenge',
		'code_challenge_method',
		'resource',
		'scope',
		'state',
	);

	/**
	 * Creates the authorization controller.
	 *
	 * @since 0.1.0
	 *
	 * @param SiteState            $siteState    Site lifecycle and identity.
	 * @param AuthorizationService $authorization Authorization service.
	 */
	public function __construct(
		private readonly SiteState $siteState,
		private readonly AuthorizationService $authorization
	) {
	}

	/**
	 * Handles authorization for an authenticated WordPress user.
	 *
	 * @since 0.1.0
	 */
	public function handle(): void {
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Raw server transport metadata is checked against one fixed method.
		$method = is_string( $method ) ? $method : 'GET';
		if ( 'POST' === strtoupper( $method ) ) {
			$this->completeConsent();
			return;
		}

		try {
			$consent = $this->authorization->begin( self::authorizationParametersFromQuery(), get_current_user_id() );
			if ( is_int( $consent['reusable_grant_id'] ) ) {
				$redirect = $this->authorization->complete(
					$consent['transaction'],
					get_current_user_id(),
					true,
					$consent['reusable_grant_id']
				);
				wp_redirect( $redirect, 302, 'Charter' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- The destination was loaded from an exact pre-registered redirect binding.
				exit;
			}
			$this->renderConsent( $consent['transaction'], $consent['request'] );
		} catch ( ProtocolException $exception ) {
			$this->handleError( $exception );
		}
	}

	/**
	 * Validates a logged-out request before redirecting to WordPress login.
	 *
	 * @since 0.1.0
	 *
	 * @throws ProtocolException Internally normalized to an authorization response.
	 */
	public function handleLoggedOut(): void {
		try {
			$parameters = self::authorizationParametersFromQuery();
			$request    = $this->authorization->validate( $parameters );
			$identity   = $this->siteState->identity();
			if ( null === $identity ) {
				throw new ProtocolException( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
			}

			$loginReturn = AuthorizationService::redirectWithParameters(
				( new EndpointUrls( $identity->issuer() ) )->authorizationEndpoint(),
				self::requestParameters( $request )
			);
			wp_safe_redirect( wp_login_url( $loginReturn ) );
			exit;
		} catch ( ProtocolException $exception ) {
			$this->handleError( $exception );
		}
	}

	/**
	 * Consumes a nonce-protected consent transaction.
	 *
	 * @since 0.1.0
	 */
	private function completeConsent(): void {
		$transaction = self::scalarInput( $_POST['transaction'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- The helper unslashes this opaque bounded value before the transaction-bound nonce verifies it.
		$nonce       = self::scalarInput( $_POST['_wpnonce'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- The helper unslashes this nonce before immediate verification.

		if ( '' === $transaction || ! wp_verify_nonce( $nonce, 'charter_oauth_consent:' . $transaction ) ) {
			$this->renderError( 'invalid_request', 'The authorization consent is invalid or expired.', 400 );
		}

		$approved = 'approve' === self::scalarInput( $_POST['decision'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- The helper unslashes this value before one fixed comparison covered by the verified nonce.

		try {
			$redirect = $this->authorization->complete( $transaction, get_current_user_id(), $approved );
			wp_redirect( $redirect, 302, 'Charter' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- The destination was loaded from an exact pre-registered redirect binding.
			exit;
		} catch ( ProtocolException $exception ) {
			$this->handleError( $exception );
		}
	}

	/**
	 * Renders the exact consent facts and transaction-bound actions.
	 *
	 * @since 0.1.0
	 *
	 * @param string               $transaction Opaque consent transaction.
	 * @param AuthorizationRequest $request     Validated request.
	 */
	private function renderConsent( string $transaction, AuthorizationRequest $request ): void {
		$identity = $this->siteState->identity();
		if ( null === $identity ) {
			$this->renderError( 'temporarily_unavailable', 'The OAuth issuer is not enabled.', 503 );
		}

		$action          = ( new EndpointUrls( $identity->issuer() ) )->authorizationEndpoint();
		$redirectHost    = wp_parse_url( $request->redirectUri(), PHP_URL_HOST );
		$redirectHost    = is_string( $redirectHost ) ? $redirectHost : $request->redirectUri();
		$nonce           = wp_nonce_field( 'charter_oauth_consent:' . $transaction, '_wpnonce', true, false );
		$scopeHtml       = self::scopeConsentHtml( $request );
		$scriptNonce     = bin2hex( random_bytes( 16 ) );
		$scriptHtml      = self::consentScriptHtml( $scriptNonce );
		$loopbackWarning = self::hasOnlyLoopbackRedirects( $request )
			? '<p class="charter-consent__warning"><strong>' . esc_html__( 'Local callback warning:', 'charter' ) . '</strong> ' . esc_html__( 'Another process on your device could impersonate this client and receive the authorization response.', 'charter' ) . '</p>'
			: '';
		$html            = self::consentStyleHtml() . sprintf(
			'<div class="charter-consent"><p class="charter-consent__trust">%1$s</p><div class="charter-consent__body"><h1>%2$s</h1><p class="charter-consent__lead"><strong>%3$s</strong> %4$s</p><dl><dt>%5$s</dt><dd>%6$s</dd><dt>%7$s</dt><dd>%8$s</dd><dt>%9$s</dt><dd>%10$s</dd><dt>%11$s</dt><dd>%12$s</dd></dl><p class="charter-consent__guardrail">%13$s</p>%14$s<form method="post" action="%15$s" data-charter-oauth-consent>%16$s<input type="hidden" name="transaction" value="%17$s"><p class="charter-consent__actions"><button type="submit" name="decision" value="approve" class="button button-primary">%18$s</button><button type="submit" name="decision" value="deny" class="button">%19$s</button></p><p class="charter-consent__status" data-charter-oauth-status role="status" aria-live="polite" hidden>%20$s</p></form></div></div>%21$s',
			esc_html__( 'Secure WordPress authorization', 'charter' ),
			esc_html__( 'Authorize WordPress access', 'charter' ),
			esc_html( $request->client()->name() ),
			esc_html__( 'is requesting delegated access.', 'charter' ),
			esc_html__( 'Protected resource', 'charter' ),
			esc_html( $request->resource() ),
			esc_html__( 'Requested access', 'charter' ),
			$scopeHtml,
			esc_html__( 'Redirect host', 'charter' ),
			esc_html( $redirectHost ),
			esc_html__( 'Continuing access', 'charter' ),
			$request->continuingAccessRequested()
				? esc_html__( 'Requested. Approval allows this client to use rotating refresh tokens until the grant expires or is revoked.', 'charter' )
				: esc_html__( 'Not requested.', 'charter' ),
			esc_html__( 'WordPress permissions still control every operation performed as your account.', 'charter' ),
			$loopbackWarning,
			esc_url( $action ),
			$nonce,
			esc_attr( $transaction ),
			esc_html__( 'Approve', 'charter' ),
			esc_html__( 'Deny', 'charter' ),
			esc_html__( 'Completing authorization…', 'charter' ),
			$scriptHtml
		);

		$this->sendHtmlHeaders( $scriptNonce, $request->redirectUri() );
		wp_die( $html, esc_html__( 'OAuth authorization', 'charter' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Every dynamic value in the assembled consent HTML is escaped.
	}

	/**
	 * Returns the standalone consent-page visual treatment.
	 *
	 * @return string Scoped inline style markup permitted by the response CSP.
	 */
	private static function consentStyleHtml(): string {
		return <<<'HTML'
<style>
:root { color-scheme: light; }
body { background: #f0f0f1 !important; }
body #error-page { width: min(100% - 40px, 640px); max-width: none; margin: 48px auto; padding: 0; background: #fff; border: 1px solid #dcdcde; border-radius: 4px; box-shadow: 0 1px 2px rgba(0, 0, 0, .05); }
body #error-page > p, body #error-page > .wp-die-message { margin: 0; }
.charter-consent { color: #1e1e1e; }
.charter-consent * { box-sizing: border-box; }
.charter-consent__trust { display: flex; align-items: center; gap: 10px; margin: 0; padding: 16px 28px; color: #00450c; background: #edfaef; border-bottom: 1px solid #b8e6bf; font-size: 13px; font-weight: 600; }
.charter-consent__trust::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: #00a32a; box-shadow: 0 0 0 4px rgba(0, 163, 42, .12); }
.charter-consent__body { padding: 32px; }
.charter-consent h1 { margin: 0 0 12px; font-size: clamp(27px, 5vw, 36px); line-height: 1.15; letter-spacing: -.02em; }
.charter-consent__lead { margin: 0 0 28px; color: #50575e; font-size: 16px; line-height: 1.55; }
.charter-consent dl { display: grid; grid-template-columns: minmax(128px, .65fr) minmax(0, 1.35fr); margin: 0 0 24px; border: 1px solid #dcdcde; border-radius: 3px; overflow: hidden; }
.charter-consent dt, .charter-consent dd { margin: 0; padding: 14px 16px; border-bottom: 1px solid #dcdcde; font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; }
.charter-consent dt { color: #50575e; background: #f6f7f7; font-weight: 600; }
.charter-consent dd { color: #1e1e1e; }
.charter-consent dt:last-of-type, .charter-consent dd:last-of-type { border-bottom: 0; }
.charter-consent__guardrail { margin: 0 0 24px; padding: 14px 16px; color: #3c434a; background: #f6f7f7; border-left: 3px solid #3858e9; font-size: 14px; line-height: 1.55; }
.charter-consent__warning { margin: 0 0 24px; padding: 14px 16px; color: #3c434a; background: #fcf9e8; border-left: 3px solid #dba617; font-size: 14px; line-height: 1.55; }
.charter-consent__actions { display: flex; align-items: center; gap: 10px; margin: 0; }
.charter-consent .button { display: inline-flex; align-items: center; justify-content: center; min-height: 40px; margin: 0; padding: 0 18px; border: 1px solid #8c8f94; border-radius: 2px; font-weight: 600; text-decoration: none; cursor: pointer; }
.charter-consent .button-primary { color: #fff; background: #3858e9; border-color: #3858e9; }
.charter-consent .button-primary:hover { background: #1d35b4; border-color: #1d35b4; }
.charter-consent .button:not(.button-primary) { color: #2c3338; background: #fff; }
.charter-consent .button:focus-visible { outline: 2px solid #3858e9; outline-offset: 2px; }
.charter-consent__status { margin: 16px 0 0; color: #50575e; font-size: 13px; }
@media (max-width: 560px) {
	body #error-page { width: min(100% - 24px, 640px); margin: 24px auto; }
	.charter-consent__body { padding: 24px; }
	.charter-consent dl { grid-template-columns: 1fr; }
	.charter-consent dt, .charter-consent dd { border-bottom: 1px solid #dcdcde; }
	.charter-consent dd:last-of-type { border-bottom: 0; }
	.charter-consent__actions { align-items: stretch; flex-direction: column; }
	.charter-consent .button { width: 100%; }
}
</style>
HTML;
	}

	/**
	 * Renders the queued consent interaction script for the standalone wp_die document.
	 *
	 * @param string $nonce Per-response Content Security Policy nonce.
	 * @return string WordPress-generated script markup.
	 */
	private static function consentScriptHtml( string $nonce ): string {
		$scriptPath = CHARTER_PATH . 'assets/js/oauth-consent.js';
		$digest     = hash_file( 'sha256', $scriptPath );
		$version    = CHARTER_VERSION . ( is_string( $digest ) ? '.' . substr( $digest, 0, 12 ) : '' );
		$addNonce   = static function ( array $attributes ) use ( $nonce ): array {
			if ( 'charter-oauth-consent-js' === ( $attributes['id'] ?? null ) ) {
				$attributes['nonce'] = $nonce;
			}

			return $attributes;
		};

		wp_enqueue_script(
			'charter-oauth-consent',
			plugins_url( 'assets/js/oauth-consent.js', CHARTER_FILE ),
			array(),
			$version,
			array(
				'in_footer' => false,
				'strategy'  => 'defer',
			)
		);

		add_filter( 'wp_script_attributes', $addNonce );
		$bufferLevel = ob_get_level();
		ob_start();
		$html = '';
		try {
			wp_print_scripts( 'charter-oauth-consent' );
			$printed = ob_get_clean();
			$html    = is_string( $printed ) ? $printed : '';
		} finally {
			remove_filter( 'wp_script_attributes', $addNonce );
			while ( ob_get_level() > $bufferLevel ) {
				ob_end_clean();
			}
		}

		return $html;
	}

	/**
	 * Renders registered user-facing scope names and descriptions.
	 *
	 * @param AuthorizationRequest $request Validated authorization request.
	 */
	private static function scopeConsentHtml( AuthorizationRequest $request ): string {
		$items = array();
		foreach ( $request->consentScopes() as $scope ) {
			$items[] = sprintf(
				'<li><strong>%1$s</strong> <code>%2$s</code><br>%3$s</li>',
				esc_html( $scope->name() ),
				esc_html( $scope->identifier() ),
				esc_html( $scope->description() )
			);
		}

		return '<ul>' . implode( '', $items ) . '</ul>';
	}

	/**
	 * Reports whether a CIMD client publishes only device-local callback hosts.
	 *
	 * @param AuthorizationRequest $request Validated authorization request.
	 */
	private static function hasOnlyLoopbackRedirects( AuthorizationRequest $request ): bool {
		if ( ClientRegistry::SOURCE_CIMD !== $request->client()->source() || array() === $request->client()->redirectUris() ) {
			return false;
		}
		foreach ( $request->client()->redirectUris() as $redirectUri ) {
			$host = wp_parse_url( $redirectUri, PHP_URL_HOST );
			if ( ! is_string( $host ) || ! in_array( strtolower( trim( $host, '[]' ) ), array( 'localhost', '127.0.0.1', '::1' ), true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Redirects safe OAuth errors or renders a local error.
	 *
	 * @since 0.1.0
	 *
	 * @param ProtocolException $exception Bounded protocol error.
	 */
	private function handleError( ProtocolException $exception ): void {
		if ( null !== $exception->redirectUri() ) {
			$identity = $this->siteState->identity();
			$redirect = AuthorizationService::redirectWithParameters(
				$exception->redirectUri(),
				array(
					'error'             => $exception->error(),
					'error_description' => $exception->getMessage(),
					'state'             => $exception->state(),
					'iss'               => null === $identity ? null : $identity->issuer(),
				)
			);
			wp_redirect( $redirect, 302, 'Charter' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- The exception carries only a prevalidated registered redirect.
			exit;
		}
		if ( is_int( $exception->retryAfter() ) ) {
			header( 'Retry-After: ' . max( 1, $exception->retryAfter() ) );
		}

		$this->renderError( $exception->error(), $exception->getMessage(), $exception->status() );
	}

	/**
	 * Renders a local authorization error without exposing client state.
	 *
	 * @since 0.1.0
	 *
	 * @param string $error       OAuth error code.
	 * @param string $description Safe public description.
	 * @param int    $status      HTTP response status.
	 */
	private function renderError( string $error, string $description, int $status ): never {
		$this->sendHtmlHeaders();
		wp_die(
			esc_html( $error . ': ' . $description ),
			esc_html__( 'OAuth authorization error', 'charter' ),
			array( 'response' => $status ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- The response status is a typed integer, not output.
		);
	}

	/**
	 * Applies browser authorization response hardening.
	 *
	 * @since 0.1.0
	 *
	 * @param string|null $scriptNonce Optional nonce for the consent interaction script.
	 * @param string|null $redirectUri Optional validated OAuth callback URI.
	 */
	private function sendHtmlHeaders( ?string $scriptNonce = null, ?string $redirectUri = null ): void {
		$scriptPolicy   = null === $scriptNonce ? '' : " script-src 'nonce-" . $scriptNonce . "';";
		$formAction     = null === $redirectUri ? null : self::cspOrigin( $redirectUri );
		$formActionList = "'self'" . ( null === $formAction ? '' : ' ' . $formAction );

		nocache_headers();
		header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline';" . $scriptPolicy . ' form-action ' . $formActionList . "; frame-ancestors 'none'; base-uri 'none'" );
		header( 'X-Frame-Options: DENY' );
		header( 'Referrer-Policy: no-referrer' );
	}

	/**
	 * Returns the exact origin source expression for one validated callback.
	 *
	 * CSP redirect matching ignores source paths, so the validated callback
	 * origin is the narrowest source that permits the authorization response.
	 *
	 * @param string $uri Validated OAuth callback URI.
	 */
	private static function cspOrigin( string $uri ): ?string {
		$parts = wp_parse_url( $uri );
		if (
			false === $parts
			|| ! is_string( $parts['scheme'] ?? null )
			|| ! is_string( $parts['host'] ?? null )
			|| ! in_array( strtolower( $parts['scheme'] ), array( 'http', 'https' ), true )
		) {
			return null;
		}

		$host = strtolower( trim( $parts['host'], '[]' ) );
		if ( str_contains( $host, ':' ) ) {
			$host = '[' . $host . ']';
		}

		return strtolower( $parts['scheme'] ) . '://' . $host . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );
	}

	/**
	 * Reads exact, unique OAuth parameters from the raw query.
	 *
	 * @since 0.1.0
	 *
	 * @return array<string, string> Unslashed exact parameter values.
	 * @throws ProtocolException When the query is too large or ambiguous.
	 */
	private static function authorizationParametersFromQuery(): array {
		$query = $_SERVER['QUERY_STRING'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Raw server transport metadata is parsed below without PHP's lossy parameter-name normalization.
		$query = is_string( $query ) ? $query : '';
		if ( strlen( $query ) > 16384 ) {
			throw new ProtocolException( 'invalid_request', 'The authorization request is too large.' );
		}

		$parameters = array();
		foreach ( explode( '&', $query ) as $pair ) {
			if ( '' === $pair ) {
				continue;
			}

			$parts = explode( '=', $pair, 2 );
			$name  = urldecode( $parts[0] );
			if ( ! in_array( $name, self::PARAMETERS, true ) ) {
				continue;
			}
			if ( array_key_exists( $name, $parameters ) ) {
				throw new ProtocolException( 'invalid_request', 'The authorization request contains duplicate parameters.' );
			}

			$parameters[ $name ] = urldecode( $parts[1] ?? '' );
		}

		return $parameters;
	}

	/**
	 * Recreates validated request parameters for post-login continuation.
	 *
	 * @since 0.1.0
	 *
	 * @param AuthorizationRequest $request Validated request.
	 * @return array<string, string|null> Exact request parameters.
	 */
	private static function requestParameters( AuthorizationRequest $request ): array {
		return array(
			'response_type'         => 'code',
			'client_id'             => $request->client()->clientId(),
			'redirect_uri'          => $request->redirectUri(),
			'code_challenge'        => $request->codeChallenge(),
			'code_challenge_method' => 'S256',
			'resource'              => $request->resource(),
			'scope'                 => $request->continuingAccessRequested()
				? $request->scope() . ' ' . AuthorizationService::OFFLINE_ACCESS_SCOPE
				: $request->scope(),
			'state'                 => $request->state(),
		);
	}

	/**
	 * Reads a scalar form value without normalization.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $value Raw form value.
	 */
	private static function scalarInput( mixed $value ): string {
		return is_string( $value ) ? wp_unslash( $value ) : '';
	}
}

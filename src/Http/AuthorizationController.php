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
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Runtime type and fixed method comparison only.
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
		$transaction = self::scalarInput( $_POST['transaction'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- The nonce action is derived from this bounded opaque value.
		$nonce       = self::scalarInput( $_POST['_wpnonce'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified immediately below.

		if ( '' === $transaction || ! wp_verify_nonce( $nonce, 'charter_oauth_consent:' . $transaction ) ) {
			$this->renderError( 'invalid_request', 'The authorization consent is invalid or expired.', 400 );
		}

		$approved = 'approve' === self::scalarInput( $_POST['decision'] ?? null ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Covered by the transaction-bound nonce above.

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

		$action       = ( new EndpointUrls( $identity->issuer() ) )->authorizationEndpoint();
		$redirectHost = wp_parse_url( $request->redirectUri(), PHP_URL_HOST );
		$redirectHost = is_string( $redirectHost ) ? $redirectHost : $request->redirectUri();
		$nonce        = wp_nonce_field( 'charter_oauth_consent:' . $transaction, '_wpnonce', true, false );
		$html         = sprintf(
			'<h1>%1$s</h1><p><strong>%2$s</strong> %3$s</p><dl><dt>%4$s</dt><dd>%5$s</dd><dt>%6$s</dt><dd>%7$s</dd><dt>%8$s</dt><dd>%9$s</dd><dt>%10$s</dt><dd>%11$s</dd></dl><p>%12$s</p><form method="post" action="%13$s">%14$s<input type="hidden" name="transaction" value="%15$s"><p><button type="submit" name="decision" value="approve" class="button button-primary">%16$s</button> <button type="submit" name="decision" value="deny" class="button">%17$s</button></p></form>',
			esc_html__( 'Authorize WordPress access', 'charter' ),
			esc_html( $request->client()->name() ),
			esc_html__( 'is requesting delegated access.', 'charter' ),
			esc_html__( 'Protected resource', 'charter' ),
			esc_html( $request->resource() ),
			esc_html__( 'Scope', 'charter' ),
			esc_html( $request->scope() ),
			esc_html__( 'Redirect host', 'charter' ),
			esc_html( $redirectHost ),
			esc_html__( 'Continuing access', 'charter' ),
			$request->continuingAccessRequested()
				? esc_html__( 'Requested. Approval allows this client to use rotating refresh tokens until the grant expires or is revoked.', 'charter' )
				: esc_html__( 'Not requested.', 'charter' ),
			esc_html__( 'WordPress permissions still control every operation performed as your account.', 'charter' ),
			esc_url( $action ),
			$nonce,
			esc_attr( $transaction ),
			esc_html__( 'Approve', 'charter' ),
			esc_html__( 'Deny', 'charter' )
		);

		$this->sendHtmlHeaders();
		wp_die( $html, esc_html__( 'OAuth authorization', 'charter' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Every dynamic value in the assembled consent HTML is escaped.
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
	 */
	private function sendHtmlHeaders(): void {
		nocache_headers();
		header( "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" );
		header( 'X-Frame-Options: DENY' );
		header( 'Referrer-Policy: no-referrer' );
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
		$query = $_SERVER['QUERY_STRING'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed below without using PHP's lossy parameter-name normalization.
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

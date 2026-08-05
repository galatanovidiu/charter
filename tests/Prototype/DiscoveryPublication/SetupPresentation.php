<?php
/**
 * Disposable Slice 0 setup presentation.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\DiscoveryPublication;

/**
 * Produces exact, non-secret external verification guidance.
 *
 * @since 0.1.0
 */
final class SetupPresentation {

	/**
	 * Presents every required discovery URL and observation.
	 *
	 * @since 0.1.0
	 *
	 * @param string $issuer         The exact established issuer.
	 * @param array  $resources      The isolated resources.
	 * @param bool   $development    Whether the site uses explicit development mode.
	 * @param string $intendedClient The intended local client description.
	 * @return array{
	 *     issuer: string,
	 *     verification_urls: list<string>,
	 *     expected: array{
	 *         status: int,
	 *         content_type: string,
	 *         body_class: string,
	 *         redirect: bool,
	 *         identity_by_url: array<string, string>,
	 *         access_control_allow_origin: string,
	 *         access_control_allow_credentials: bool,
	 *         cache_control: string,
	 *         content_location: string,
	 *         backend_reference_present: bool
	 *     },
	 *     browser_instructions: string,
	 *     curl_command: string,
	 *     real_client_instructions: string,
	 *     development_warning: string|null
	 * } The setup presentation.
	 */
	public static function forIssuer(
		string $issuer,
		array $resources = array(),
		bool $development = false,
		string $intendedClient = 'MCP Inspector 2.0.0'
	): array {
		$authorizationServerUrl = MetadataProjector::authorizationServerUrl( $issuer );
		$protectedResourceUrl   = MetadataProjector::protectedResourceUrl( $issuer, $issuer );
		$urls                   = array( $authorizationServerUrl, $protectedResourceUrl );
		$identityByUrl          = array(
			$authorizationServerUrl => $issuer,
			$protectedResourceUrl   => $issuer,
		);

		foreach ( $resources as $resource ) {
			$url                   = MetadataProjector::protectedResourceUrl( $issuer, $resource );
			$urls[]                = $url;
			$identityByUrl[ $url ] = $resource;
		}

		$curlCommand = implode(
			"\n",
			array(
				'charter_issuer=' . escapeshellarg( $issuer ),
				'env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \\',
				'  -u http_proxy -u https_proxy -u all_proxy \\',
				'  curl --disable --silent --show-error --fail-with-body \\',
				"  --proto '=https' --request GET --header 'Accept: application/json' \\",
				'  --connect-timeout 5 --max-time 10 --max-filesize 65536 \\',
				'  "$charter_issuer/.well-known/oauth-authorization-server"',
			)
		);

		$developmentWarning = null;

		if ( $development ) {
			$developmentWarning = 'In insecure development mode, verify from the intended local client: '
				. $intendedClient
				. '. This does not establish production reachability.';
		}

		return array(
			'issuer'                   => $issuer,
			'verification_urls'        => $urls,
			'expected'                 => array(
				'status'                           => 200,
				'content_type'                     => 'application/json',
				'body_class'                       => 'json',
				'redirect'                         => false,
				'identity_by_url'                  => $identityByUrl,
				'access_control_allow_origin'      => '*',
				'access_control_allow_credentials' => false,
				'cache_control'                    => 'no-store',
				'content_location'                 => 'exact requested URL',
				'backend_reference_present'        => false,
			),
			'browser_instructions'     => 'Open each exact URL, confirm HTTP 200 JSON, compare the displayed issuer/resource identity, require CORS *, no credentials, Cache-Control no-store, and Content-Location equal to the requested URL; reject redirects, HTML, errors, or backend references.',
			'curl_command'             => $curlCommand,
			'real_client_instructions' => 'Use MCP Inspector 2.0.0 UI to observe protected-resource metadata followed by authorization-server metadata; stop before grant behavior and do not treat a generic CLI connection as OAuth discovery evidence.',
			'development_warning'      => $developmentWarning,
		);
	}
}

<?php
/**
 * Direct connection-bound CIMD JSON transport.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Http;

use CurlHandle;
use GalatanOvidiu\Charter\OAuth\ClientMetadataIdentifier;
use GalatanOvidiu\Charter\OAuth\ClientMetadataResolutionException;

/**
 * Binds screened addresses to one fresh cURL connection with no proxy or retry.
 *
 * This deliberately uses cURL directly: WordPress Requests can retry callback
 * aborts and its response-size option is a truncation control, not a complete
 * transfer boundary.
 */
final class BoundedDirectJsonFetcher implements RemoteJsonFetcher {

	/**
	 * Complete response body.
	 *
	 * @var string
	 */
	private string $body = '';

	/**
	 * Duplicate-preserving response headers.
	 *
	 * @var array<string,list<string>>
	 */
	private array $headers = array();

	/**
	 * Aggregate header bytes.
	 *
	 * @var int
	 */
	private int $headerBytes = 0;

	/**
	 * Aggregate header field count.
	 *
	 * @var int
	 */
	private int $headerFields = 0;

	/**
	 * Aggregate body bytes.
	 *
	 * @var int
	 */
	private int $bodyBytes = 0;

	/**
	 * Final response status.
	 *
	 * @var int
	 */
	private int $status = 0;

	/**
	 * Accepted connection count.
	 *
	 * @var int
	 */
	private int $requestCount = 0;

	/**
	 * Whether the connected peer matched the screened set.
	 *
	 * @var bool
	 */
	private bool $peerMatched = false;

	/**
	 * Sanitized callback abort classification.
	 *
	 * @var string|null
	 */
	private ?string $abortClassification = null;

	/**
	 * Creates the direct transport.
	 *
	 * @param string|null $certificateAuthorityFile Optional test certificate authority file.
	 */
	public function __construct( private readonly ?string $certificateAuthorityFile = null ) {
	}

	/**
	 * Verifies that the exact safe transport policy can be enforced.
	 *
	 * @throws ClientMetadataResolutionException When direct safe transport is unavailable.
	 */
	public function assertAvailable(): void {
		$functions = array( 'curl_init', 'curl_exec', 'curl_getinfo', 'curl_errno', 'curl_setopt_array', 'curl_version' );
		foreach ( $functions as $function ) {
			if ( ! function_exists( $function ) ) {
				throw new ClientMetadataResolutionException( 'transport_unavailable' );
			}
		}
		foreach ( array( 'CURLOPT_RESOLVE', 'CURLOPT_PREREQFUNCTION', 'CURLINFO_PRIMARY_IP', 'CURLOPT_FRESH_CONNECT', 'CURLOPT_FORBID_REUSE', 'CURLOPT_PROXY', 'CURLOPT_NOPROXY', 'CURL_PREREQFUNC_OK', 'CURL_PREREQFUNC_ABORT' ) as $constant ) {
			if ( ! defined( $constant ) ) {
				throw new ClientMetadataResolutionException( 'transport_unavailable' );
			}
		}
		$version = curl_version();
		if ( ! is_array( $version ) || ! is_string( $version['version'] ?? null ) || version_compare( $version['version'], '7.80.0', '<' ) ) {
			throw new ClientMetadataResolutionException( 'transport_unavailable' );
		}
		foreach ( array( 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy' ) as $name ) {
			$value = getenv( $name );
			if ( is_string( $value ) && '' !== trim( $value ) ) {
				throw new ClientMetadataResolutionException( 'proxy_configured' );
			}
		}
		if ( class_exists( '\WP_HTTP_Proxy' ) && ( new \WP_HTTP_Proxy() )->is_enabled() ) {
			throw new ClientMetadataResolutionException( 'proxy_configured' );
		}
		$caFile = $this->caFile();
		if ( ! is_file( $caFile ) || ! is_readable( $caFile ) ) {
			throw new ClientMetadataResolutionException( 'transport_unavailable' );
		}
	}

	/**
	 * Fetches one exact metadata URL through a screened fresh connection.
	 *
	 * @param ClientMetadataIdentifier $identifier Exact submitted identifier.
	 * @param array                    $screenedAddresses Complete screened terminal addresses.
	 * @phpstan-param list<string> $screenedAddresses
	 * @throws ClientMetadataResolutionException When the response is not authoritative.
	 */
	public function fetch( ClientMetadataIdentifier $identifier, array $screenedAddresses ): BoundedHttpResponse {
		$this->assertAvailable();
		$this->reset();
		$accepted = array();
		foreach ( $screenedAddresses as $address ) {
			$packed = inet_pton( $address );
			if ( false === $packed ) {
				throw new ClientMetadataResolutionException( 'peer_invalid' );
			}
			$accepted[ bin2hex( $packed ) ] = $address;
		}
		if ( array() === $accepted ) {
			throw new ClientMetadataResolutionException( 'peer_invalid' );
		}

		$handle = curl_init( $identifier->exact() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_init -- Direct cURL is required for screened connection binding and bounded callbacks.
		if ( ! $handle instanceof CurlHandle ) {
			throw new ClientMetadataResolutionException( 'transport_unavailable' );
		}
		$resolveAddresses = array_map( static fn ( string $address ): string => str_contains( $address, ':' ) ? '[' . $address . ']' : $address, array_values( $accepted ) );
		$resolveEntry     = $identifier->host() . ':443:' . implode( ',', $resolveAddresses );
		$requestTime      = time();
		$caFile           = $this->caFile();
		if ( '' === $caFile ) {
			throw new ClientMetadataResolutionException( 'transport_unavailable' );
		}
		$options = array(
			CURLOPT_HTTPGET           => true,
			CURLOPT_CUSTOMREQUEST     => 'GET',
			CURLOPT_HTTPHEADER        => array( 'Accept: application/json', 'Accept-Encoding: identity', 'Cache-Control: no-cache', 'User-Agent: Charter-CIMD/0.1' ),
			CURLOPT_CONNECTTIMEOUT    => 3,
			CURLOPT_TIMEOUT           => 5,
			CURLOPT_FOLLOWLOCATION    => false,
			CURLOPT_MAXREDIRS         => 0,
			CURLOPT_SSL_VERIFYPEER    => true,
			CURLOPT_SSL_VERIFYHOST    => 2,
			CURLOPT_CAINFO            => $caFile,
			CURLOPT_PROXY             => '',
			CURLOPT_NOPROXY           => '*',
			CURLOPT_RESOLVE           => array( $resolveEntry ),
			CURLOPT_FRESH_CONNECT     => true,
			CURLOPT_FORBID_REUSE      => true,
			CURLOPT_AUTOREFERER       => false,
			CURLOPT_UNRESTRICTED_AUTH => false,
			CURLOPT_FAILONERROR       => false,
			CURLOPT_HEADER            => false,
			CURLOPT_RETURNTRANSFER    => false,
			CURLOPT_PREREQFUNCTION    => function ( CurlHandle $unused, string $primaryIp, string $localIp, int $primaryPort, int $localPort ) use ( $accepted ): int {
				unset( $unused, $localIp, $localPort );
				$packed = inet_pton( $primaryIp );
				if ( false === $packed || 443 !== $primaryPort || ! isset( $accepted[ bin2hex( $packed ) ] ) || 0 !== $this->requestCount ) {
					$this->abortClassification = 'peer_mismatch';
					return CURL_PREREQFUNC_ABORT;
				}
				$this->peerMatched = true;
				++$this->requestCount;
				return CURL_PREREQFUNC_OK;
			},
			CURLOPT_HEADERFUNCTION    => fn ( CurlHandle $unused, string $line ): int => $this->captureHeader( $line ),
			CURLOPT_WRITEFUNCTION     => fn ( CurlHandle $unused, string $chunk ): int => $this->captureBody( $chunk ),
		);
		if ( defined( 'CURLOPT_PROTOCOLS' ) && defined( 'CURLPROTO_HTTPS' ) ) {
			$options[ CURLOPT_PROTOCOLS ] = CURLPROTO_HTTPS;
		}
		if ( ! curl_setopt_array( $handle, $options ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt_array -- Required exact direct-transport policy.
			throw new ClientMetadataResolutionException( 'transport_unavailable' );
		}

		curl_exec( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_exec -- Required single direct send with bounded callbacks.
		$responseTime = time();
		$error        = curl_errno( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_errno -- Sanitized classification only.
		$status       = (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_getinfo -- Required connected-response verification.
		$primaryIp    = (string) curl_getinfo( $handle, CURLINFO_PRIMARY_IP ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_getinfo -- Required peer verification.
		$verifyResult = (int) curl_getinfo( $handle, CURLINFO_SSL_VERIFYRESULT ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_getinfo -- Required TLS verification result.
		$redirects    = (int) curl_getinfo( $handle, CURLINFO_REDIRECT_COUNT ); // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_getinfo -- Required no-redirect assertion.
		unset( $handle );

		$packedPeer = inet_pton( $primaryIp );
		if ( null !== $this->abortClassification ) {
			throw new ClientMetadataResolutionException( $this->abortClassification ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Sanitized internal classification, not output.
		}
		if ( 0 !== $error ) {
			throw new ClientMetadataResolutionException( 'transport_failed' );
		}
		if ( 1 !== $this->requestCount || ! $this->peerMatched || false === $packedPeer || ! isset( $accepted[ bin2hex( $packedPeer ) ] ) ) {
			throw new ClientMetadataResolutionException( 'peer_mismatch' );
		}
		if ( 0 !== $verifyResult ) {
			throw new ClientMetadataResolutionException( 'tls_failed' );
		}
		if ( 0 !== $redirects || ( 300 <= $status && 400 > $status ) ) {
			throw new ClientMetadataResolutionException( 'redirect_rejected' );
		}
		if ( 200 !== $status || $this->status !== $status ) {
			throw new ClientMetadataResolutionException( 'status_rejected' );
		}
		$this->assertRepresentationHeaders();

		return new BoundedHttpResponse( $this->body, $this->headers, $requestTime, $responseTime );
	}

	/**
	 * Captures one bounded response header line.
	 *
	 * @param string $line Exact response header line.
	 * @return int Accepted byte count, or zero to abort.
	 */
	private function captureHeader( string $line ): int {
		$length = strlen( $line );
		if ( 8192 < $length || 32768 < $this->headerBytes + $length ) {
			$this->abortClassification = 'header_limit';
			return 0;
		}
		if ( str_starts_with( $line, 'HTTP/' ) ) {
			$this->headers = array();
			$this->status  = 0;
			if ( 1 === preg_match( '/\AHTTP\/[0-9]+(?:\.[0-9]+)?[ \t]+([0-9]{3})(?:[ \t]|\r|\n)/D', $line, $matches ) ) {
				$this->status = (int) $matches[1];
			}
		} elseif ( "\r\n" !== $line && "\n" !== $line && '' !== $line ) {
			if ( 128 < ++$this->headerFields ) {
				$this->abortClassification = 'header_limit';
				return 0;
			}
			$separator = strpos( $line, ':' );
			$name      = false === $separator ? '' : strtolower( trim( substr( $line, 0, $separator ) ) );
			if ( false === $separator || 1 !== preg_match( "/\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\\z/", $name ) ) {
				$this->abortClassification = 'header_invalid';
				return 0;
			}
			$this->headers[ $name ][] = trim( substr( $line, $separator + 1 ) );
		}
		$this->headerBytes += $length;

		return $length;
	}

	/**
	 * Captures one bounded response body chunk.
	 *
	 * @param string $chunk Exact response body chunk.
	 * @return int Accepted byte count, or zero to abort.
	 */
	private function captureBody( string $chunk ): int {
		$length = strlen( $chunk );
		if ( 5120 < $this->bodyBytes + $length ) {
			$this->abortClassification = 'body_limit';
			return 0;
		}
		$this->body      .= $chunk;
		$this->bodyBytes += $length;

		return $length;
	}

	/**
	 * Validates the final representation headers.
	 *
	 * @throws ClientMetadataResolutionException When media, coding, or length is ambiguous.
	 */
	private function assertRepresentationHeaders(): void {
		$contentTypes = $this->headers['content-type'] ?? array();
		if ( 1 !== count( $contentTypes ) ) {
			throw new ClientMetadataResolutionException( 'media_rejected' );
		}
		$token     = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
		$quoted    = '"(?:[^"\\\\\r\n]|\\\\.)*"';
		$parameter = ';[ \\t]*' . $token . '[ \\t]*=[ \\t]*(?:' . $token . '|' . $quoted . ')[ \\t]*';
		if ( 1 !== preg_match( '/\Aapplication\/(?:json|' . $token . '\+json)[ \\t]*(?:' . $parameter . ')*\z/iD', trim( $contentTypes[0] ) ) ) {
			throw new ClientMetadataResolutionException( 'media_rejected' );
		}
		$codings = $this->headers['content-encoding'] ?? array();
		if ( 1 < count( $codings ) || ( 1 === count( $codings ) && 'identity' !== strtolower( trim( $codings[0] ) ) ) ) {
			throw new ClientMetadataResolutionException( 'coding_rejected' );
		}
		$lengths = $this->headers['content-length'] ?? array();
		if ( 1 < count( $lengths ) ) {
			throw new ClientMetadataResolutionException( 'header_invalid' );
		}
		if ( 1 === count( $lengths ) && ( 1 !== preg_match( '/^[0-9]+$/D', $lengths[0] ) || 5120 < (int) $lengths[0] ) ) {
			throw new ClientMetadataResolutionException( 'body_limit' );
		}
	}

	/** Returns the configured or WordPress certificate authority bundle. */
	private function caFile(): string {
		if ( is_string( $this->certificateAuthorityFile ) ) {
			return $this->certificateAuthorityFile;
		}

		if ( ! defined( 'ABSPATH' ) || ! defined( 'WPINC' ) ) {
			return '';
		}
		$coreDirectoryName = constant( 'WPINC' );
		if ( ! is_string( $coreDirectoryName ) ) {
			return '';
		}

		return ABSPATH . $coreDirectoryName . '/certificates/ca-bundle.crt';
	}

	/** Resets all per-request transport state. */
	private function reset(): void {
		$this->body                = '';
		$this->headers             = array();
		$this->headerBytes         = 0;
		$this->headerFields        = 0;
		$this->bodyBytes           = 0;
		$this->status              = 0;
		$this->requestCount        = 0;
		$this->peerMatched         = false;
		$this->abortClassification = null;
	}
}

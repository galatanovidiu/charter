<?php
/**
 * Request-scoped WordPress/cURL boundary for the disposable CIMD proof.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\CimdOutboundSafety;

use CurlHandle;
use WpOrg\Requests\Requests;
use WpOrg\Requests\Transport\Curl;

// Direct cURL inspection is the subject of this disposable WordPress HTTP proof.
// phpcs:disable WordPress.WP.AlternativeFunctions

/**
 * Pins one screened address set to one direct WordPress cURL send.
 *
 * This class is intentionally non-final so the pure orchestration test can
 * substitute the entire system boundary without bootstrapping WordPress.
 *
 * @since 0.1.0
 */
class BoundFetchRuntime {

	/**
	 * Proof-selected certificate authority bundle.
	 *
	 * @var string|null
	 */
	private ?string $caFile;

	/**
	 * Exact active Client Identifier.
	 *
	 * @var ClientIdentifier|null
	 */
	private ?ClientIdentifier $identifier = null;

	/**
	 * Complete screened textual address set.
	 *
	 * @var list<string>
	 */
	private array $screenedAddresses = array();

	/**
	 * Binary-keyed screened address set.
	 *
	 * @var array<string, string>
	 */
	private array $screenedBinary = array();

	/**
	 * Fixed proof policy.
	 *
	 * @var array<string, mixed>
	 */
	private array $policy = array();

	/**
	 * Captured WordPress-owned cURL handle.
	 *
	 * @var CurlHandle|null
	 */
	private ?CurlHandle $handle = null;

	/**
	 * Request-scope monotonic start.
	 *
	 * @var int
	 */
	private int $startedNanoseconds = 0;

	/**
	 * Bounded accepted response body.
	 *
	 * @var string
	 */
	private string $body = '';

	/**
	 * Accepted response body bytes.
	 *
	 * @var int
	 */
	private int $bodyBytes = 0;

	/**
	 * Aggregate response header bytes.
	 *
	 * @var int
	 */
	private int $headerBytes = 0;

	/**
	 * Aggregate response header field count.
	 *
	 * @var int
	 */
	private int $headerFields = 0;

	/**
	 * Most recent bounded response status line code.
	 *
	 * @var int
	 */
	private int $capturedStatusCode = 0;

	/**
	 * Bounded current response header block.
	 *
	 * @var array<string, list<string>>
	 */
	private array $headers = array();

	/**
	 * First callback-boundary failure.
	 *
	 * @var string|null
	 */
	private ?string $abortClassification = null;

	/**
	 * Number of sends admitted past the prerequisite callback.
	 *
	 * @var int
	 */
	private int $requestCount = 0;

	/**
	 * Number of post-send hook invocations.
	 *
	 * @var int
	 */
	private int $afterSendCount = 0;

	/**
	 * Whether the direct peer matched the screened set.
	 *
	 * @var bool
	 */
	private bool $peerMatched = false;

	/**
	 * Whether cURL confirmed original-host certificate verification.
	 *
	 * @var bool
	 */
	private bool $tlsHostnameVerified = false;

	/**
	 * Whether one exact request scope is active.
	 *
	 * @var bool
	 */
	private bool $active = false;

	/**
	 * WordPress request-argument hardener.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $requestArgumentsHook = null;

	/**
	 * WordPress short-circuit neutralizer.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $preRequestHook = null;

	/**
	 * WordPress TLS verification hardener.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $sslVerificationHook = null;

	/**
	 * Requests option hardener.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $requestsBeforeRequestHook = null;

	/**
	 * Captured-handle cURL option hardener.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $curlBeforeSendHook = null;

	/**
	 * Pre-retry post-send exit.
	 *
	 * @var \Closure|null
	 */
	private ?\Closure $curlAfterSendHook = null;

	/**
	 * Creates the runtime around one proof-selected CA bundle.
	 *
	 * @param string|null $caFile Certificate authority bundle path.
	 */
	public function __construct( ?string $caFile = null ) {
		$this->caFile = $caFile;
	}

	/**
	 * Refuses a runtime lacking any mandatory direct-transport control.
	 */
	public function preflight(): string {
		if (
			! function_exists( 'wp_remote_get' )
			|| ! function_exists( 'add_filter' )
			|| ! function_exists( 'remove_filter' )
			|| ! class_exists( Requests::class )
			|| ! class_exists( Curl::class )
			|| ! function_exists( 'curl_version' )
			|| ! function_exists( 'curl_setopt_array' )
		) {
			return 'capability-unavailable';
		}

		$requiredConstants = array(
			'CURLOPT_RESOLVE',
			'CURLOPT_PREREQFUNCTION',
			'CURLINFO_PRIMARY_IP',
			'CURLINFO_SSL_VERIFYRESULT',
			'CURLOPT_FRESH_CONNECT',
			'CURLOPT_FORBID_REUSE',
			'CURLOPT_ENCODING',
			'CURLOPT_PROXY',
			'CURLOPT_NOPROXY',
			'CURL_PREREQFUNC_OK',
			'CURL_PREREQFUNC_ABORT',
		);

		foreach ( $requiredConstants as $constant ) {
			if ( ! defined( $constant ) ) {
				return 'capability-unavailable';
			}
		}

		$version = curl_version();
		if (
			! is_array( $version )
			|| ! is_string( $version['version'] ?? null )
			|| version_compare( $version['version'], '7.80.0', '<' )
		) {
			return 'capability-unavailable';
		}

		foreach ( array( 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy' ) as $name ) {
			$value = getenv( $name );
			if ( is_string( $value ) && '' !== trim( $value ) ) {
				return 'proxy-configured';
			}
		}

		if ( class_exists( '\\WP_HTTP_Proxy' ) ) {
			$proxy = new \WP_HTTP_Proxy();
			if ( $proxy->is_enabled() ) {
				return 'proxy-configured';
			}
		}

		$caFile = $this->certificateAuthorityFile();
		if ( null === $caFile || ! is_file( $caFile ) || ! is_readable( $caFile ) ) {
			return 'capability-unavailable';
		}

		return 'ready';
	}

	/**
	 * Installs exact-URL hooks for one request.
	 *
	 * @param ClientIdentifier     $id                Exact Client Identifier.
	 * @param array                $screenedAddresses Complete screened address set.
	 * @param array<string, mixed> $policy            Fixed fetch policy.
	 * @phpstan-param list<string> $screenedAddresses
	 */
	public function begin( ClientIdentifier $id, array $screenedAddresses, array $policy ): void {
		$this->resetState();

		$screened                 = AddressPolicy::assertGloballyUsableSet( $screenedAddresses );
		$this->identifier         = $id;
		$this->screenedAddresses  = $screened;
		$this->screenedBinary     = $this->binaryAddressSet( $screened );
		$this->policy             = $policy;
		$this->startedNanoseconds = hrtime( true );
		$this->active             = true;

		$this->requestArgumentsHook = function ( mixed $arguments, string $url ): array {
			if ( ! $this->isExactActiveUrl( $url ) ) {
				return is_array( $arguments ) ? $arguments : array();
			}

			return $this->wordPressArguments();
		};
		$this->preRequestHook       = function ( mixed $unused, array $arguments, string $url ): false {
			unset( $unused, $arguments, $url );
			return false;
		};
		$this->sslVerificationHook  = function ( mixed $verification, string $url ): mixed {
			return $this->isExactActiveUrl( $url ) ? $this->certificateAuthorityFile() : $verification;
		};
		$this->curlAfterSendHook    = function (): void {
			++$this->afterSendCount;
			if ( null === $this->handle ) {
				// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Fixed exception message; observation is not output.
				throw new BoundFetchException( $this->observation( 'stream-unavailable' ) );
			}

			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Fixed exception message; observation is not output.
			throw new BoundFetchException( $this->observeCompletedSend( $this->handle ) );
		};

		$this->requestsBeforeRequestHook = function (
			string &$url,
			array &$headers,
			mixed &$data,
			string &$type,
			array &$options
		): void {
			if ( ! $this->isExactActiveUrl( $url ) ) {
				return;
			}

			$type    = Requests::GET;
			$data    = array();
			$headers = $this->requestHeaders();

			$options['timeout']          = (float) $this->intPolicyValue( 'timeout', 5 );
			$options['connect_timeout']  = (float) $this->intPolicyValue( 'connect_timeout', 3 );
			$options['follow_redirects'] = false;
			$options['redirects']        = 0;
			$options['verify']           = $this->certificateAuthorityFile();
			$options['verifyname']       = true;
			$options['auth']             = false;
			$options['proxy']            = false;
			$options['cookies']          = false;
			$options['transport']        = Curl::class;
			$options['idn']              = false;
			$options['max_bytes']        = false;
			$hooks                       = $options['hooks'] ?? null;
			if ( ! is_object( $hooks ) || ! is_callable( array( $hooks, 'register' ) ) || null === $this->curlAfterSendHook ) {
				// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Fixed exception message; observation is not output.
				throw new BoundFetchException( $this->observation( 'stream-unavailable' ) );
			}
			$hooks->register( 'curl.after_send', $this->curlAfterSendHook );
		};

		$this->curlBeforeSendHook = function ( CurlHandle $handle, array $arguments, string $url ): void {
			unset( $arguments );
			if ( ! $this->isExactActiveUrl( $url ) ) {
				return;
			}

			$this->handle = $handle;
			if ( ! curl_setopt_array( $handle, $this->curlOptions() ) ) {
				// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- Fixed exception message; observation is not output.
				throw new BoundFetchException( $this->observation( 'capability-unavailable' ) );
			}
		};

		add_filter( 'http_request_args', $this->requestArgumentsHook, PHP_INT_MAX, 2 );
		add_filter( 'pre_http_request', $this->preRequestHook, PHP_INT_MAX, 3 );
		add_filter( 'https_ssl_verify', $this->sslVerificationHook, PHP_INT_MAX, 2 );
		add_action( 'requests-requests.before_request', $this->requestsBeforeRequestHook, PHP_INT_MAX, 5 );
		add_action( 'http_api_curl', $this->curlBeforeSendHook, PHP_INT_MAX, 3 );
	}

	/**
	 * Dispatches exactly once and catches only the proof-owned transport exit.
	 *
	 * @return array<string, mixed> Fixed bounded observation.
	 */
	public function dispatch(): array {
		if ( ! $this->active || null === $this->identifier ) {
			return $this->observation( 'capability-unavailable' );
		}

		try {
			wp_remote_get( $this->identifier->fetchUrl(), array() );
		} catch ( BoundFetchException $result ) {
			return $result->observation();
		}

		return $this->observation( 'stream-unavailable' );
	}

	/**
	 * Unconditionally removes every scoped hook and all captured state.
	 */
	public function end(): void {
		if ( null !== $this->requestArgumentsHook ) {
			remove_filter( 'http_request_args', $this->requestArgumentsHook, PHP_INT_MAX );
		}
		if ( null !== $this->preRequestHook ) {
			remove_filter( 'pre_http_request', $this->preRequestHook, PHP_INT_MAX );
		}
		if ( null !== $this->sslVerificationHook ) {
			remove_filter( 'https_ssl_verify', $this->sslVerificationHook, PHP_INT_MAX );
		}
		if ( null !== $this->requestsBeforeRequestHook ) {
			remove_action( 'requests-requests.before_request', $this->requestsBeforeRequestHook, PHP_INT_MAX );
		}
		if ( null !== $this->curlBeforeSendHook ) {
			remove_action( 'http_api_curl', $this->curlBeforeSendHook, PHP_INT_MAX );
		}
		$this->active                    = false;
		$this->handle                    = null;
		$this->identifier                = null;
		$this->screenedAddresses         = array();
		$this->screenedBinary            = array();
		$this->policy                    = array();
		$this->requestArgumentsHook      = null;
		$this->preRequestHook            = null;
		$this->sslVerificationHook       = null;
		$this->requestsBeforeRequestHook = null;
		$this->curlBeforeSendHook        = null;
		$this->curlAfterSendHook         = null;
	}

	/**
	 * Returns the fixed WordPress request arguments.
	 *
	 * @return array<string, mixed> Hardened WordPress arguments.
	 */
	private function wordPressArguments(): array {
		return array(
			'method'              => 'GET',
			'timeout'             => (float) $this->intPolicyValue( 'timeout', 5 ),
			'connect_timeout'     => (float) $this->intPolicyValue( 'connect_timeout', 3 ),
			'redirection'         => 0,
			'httpversion'         => '1.1',
			'user-agent'          => $this->stringPolicyValue( 'user_agent', 'Charter-CIMD-Proof/1' ),
			'headers'             => $this->requestHeaders(),
			'cookies'             => array(),
			'body'                => null,
			'compress'            => false,
			'decompress'          => false,
			'sslverify'           => true,
			'sslcertificates'     => $this->certificateAuthorityFile(),
			'stream'              => false,
			'filename'            => null,
			'limit_response_size' => null,
			'blocking'            => true,
			'reject_unsafe_urls'  => false,
		);
	}

	/**
	 * Returns the four fixed non-site-bearing request headers.
	 *
	 * @return array<string, string> Fixed request headers.
	 */
	private function requestHeaders(): array {
		return array(
			'Accept'          => $this->stringPolicyValue( 'accept', 'application/json' ),
			'Accept-Encoding' => $this->stringPolicyValue( 'accept_encoding', 'identity' ),
			'Cache-Control'   => $this->stringPolicyValue( 'cache_control', 'no-cache' ),
			'User-Agent'      => $this->stringPolicyValue( 'user_agent', 'Charter-CIMD-Proof/1' ),
		);
	}

	/**
	 * Returns final cURL options and proof-owned callbacks.
	 *
	 * @return array<int, mixed> Hardened cURL options.
	 */
	private function curlOptions(): array {
		$caFile = $this->certificateAuthorityFile();

		$options = array(
			CURLOPT_HTTPGET           => true,
			CURLOPT_CUSTOMREQUEST     => 'GET',
			CURLOPT_NOBODY            => false,
			CURLOPT_POST              => false,
			CURLOPT_UPLOAD            => false,
			CURLOPT_HTTPHEADER        => array(
				'Accept: ' . $this->stringPolicyValue( 'accept', 'application/json' ),
				'Accept-Encoding: ' . $this->stringPolicyValue( 'accept_encoding', 'identity' ),
				'Cache-Control: ' . $this->stringPolicyValue( 'cache_control', 'no-cache' ),
				'User-Agent: ' . $this->stringPolicyValue( 'user_agent', 'Charter-CIMD-Proof/1' ),
			),
			CURLOPT_CONNECTTIMEOUT    => $this->intPolicyValue( 'connect_timeout', 3 ),
			CURLOPT_TIMEOUT           => $this->intPolicyValue( 'timeout', 5 ),
			CURLOPT_FOLLOWLOCATION    => false,
			CURLOPT_MAXREDIRS         => 0,
			CURLOPT_SSL_VERIFYPEER    => true,
			CURLOPT_SSL_VERIFYHOST    => 2,
			CURLOPT_PROXY             => '',
			CURLOPT_NOPROXY           => '*',
			CURLOPT_RESOLVE           => array( $this->resolveEntry() ),
			CURLOPT_FRESH_CONNECT     => true,
			CURLOPT_FORBID_REUSE      => true,
			CURLOPT_ENCODING          => null,
			CURLOPT_AUTOREFERER       => false,
			CURLOPT_UNRESTRICTED_AUTH => false,
			CURLOPT_FAILONERROR       => false,
			CURLOPT_HEADER            => false,
			CURLOPT_PREREQFUNCTION    => function (
				CurlHandle $unused,
				string $primaryIp,
				string $localIp,
				int $primaryPort,
				int $localPort
			): int {
				unset( $unused, $localIp, $localPort );
				$binary = inet_pton( $primaryIp );
				$match  = false !== $binary
					&& 443 === $primaryPort
					&& isset( $this->screenedBinary[ bin2hex( $binary ) ] );

				if ( ! $match ) {
					$this->abortClassification = 'peer';
					return CURL_PREREQFUNC_ABORT;
				}

				$this->peerMatched = true;
				++$this->requestCount;

				return CURL_PREREQFUNC_OK;
			},
			CURLOPT_HEADERFUNCTION    => function ( CurlHandle $unused, string $line ): int {
				unset( $unused );
				return $this->captureHeaderLine( $line );
			},
			CURLOPT_WRITEFUNCTION     => function ( CurlHandle $unused, string $chunk ): int {
				unset( $unused );
				return $this->captureBodyChunk( $chunk );
			},
		);

		if ( null !== $caFile ) {
			$options[ CURLOPT_CAINFO ] = $caFile;
		}

		return $options;
	}

	/**
	 * Captures one response header line within every exact limit.
	 *
	 * @param string $line Raw bounded candidate line.
	 * @return int Consumed bytes, or zero to abort.
	 */
	private function captureHeaderLine( string $line ): int {
		$length = strlen( $line );
		if ( $length > $this->intPolicyValue( 'max_header_line_bytes', 8192 ) ) {
			$this->abortClassification = 'header-line';
			return 0;
		}

		if ( $this->headerBytes + $length > $this->intPolicyValue( 'max_header_bytes', 32768 ) ) {
			$this->abortClassification = 'header-bytes';
			return 0;
		}

		if ( str_starts_with( $line, 'HTTP/' ) ) {
			$this->headers = array();
			if ( 1 === preg_match( '/\AHTTP\/[0-9]+(?:\.[0-9]+)?[ \t]+([0-9]{3})(?:[ \t]|\r|\n)/D', $line, $matches ) ) {
				$this->capturedStatusCode = (int) $matches[1];
			}
		} elseif ( "\r\n" !== $line && "\n" !== $line && '' !== $line ) {
			if ( $this->headerFields + 1 > $this->intPolicyValue( 'max_header_fields', 128 ) ) {
				$this->abortClassification = 'header-fields';
				return 0;
			}

			++$this->headerFields;
			$separator = strpos( $line, ':' );
			if ( false === $separator ) {
				$this->abortClassification = 'media';
				return 0;
			}

			$name = strtolower( trim( substr( $line, 0, $separator ) ) );
			if ( 1 !== preg_match( "/\\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\\z/", $name ) ) {
				$this->abortClassification = 'media';
				return 0;
			}

			$this->headers[ $name ][] = trim( substr( $line, $separator + 1 ) );
		}

		$this->headerBytes += $length;
		return $length;
	}

	/**
	 * Captures one identity-coded body chunk within the exact limit.
	 *
	 * @param string $chunk Raw body chunk.
	 * @return int Consumed bytes, or zero to abort.
	 */
	private function captureBodyChunk( string $chunk ): int {
		$length = strlen( $chunk );
		if ( $this->bodyBytes + $length > $this->intPolicyValue( 'max_body_bytes', 5120 ) ) {
			$this->abortClassification = 'body-bytes';
			return 0;
		}

		$this->body      .= $chunk;
		$this->bodyBytes += $length;
		return $length;
	}

	/**
	 * Classifies one completed cURL send before Requests can retry.
	 *
	 * @param CurlHandle $handle Captured WordPress-owned handle.
	 * @return array<string, mixed> Fixed bounded observation.
	 */
	private function observeCompletedSend( CurlHandle $handle ): array {
		$status                    = (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE );
		$status                    = 0 !== $status ? $status : $this->capturedStatusCode;
		$primaryIp                 = (string) curl_getinfo( $handle, CURLINFO_PRIMARY_IP );
		$redirectCount             = (int) curl_getinfo( $handle, CURLINFO_REDIRECT_COUNT );
		$errorNumber               = curl_errno( $handle );
		$verifyResult              = (int) curl_getinfo( $handle, CURLINFO_SSL_VERIFYRESULT );
		$this->tlsHostnameVerified = $this->peerMatched
			&& 0 === $verifyResult
			&& ! in_array( $errorNumber, $this->tlsErrorNumbers(), true );
		$classification            = $this->classifyTransfer( $errorNumber, $status, $primaryIp, $redirectCount );
		$media                     = $this->classifyMediaType();
		$contentCoding             = $this->classifyContentCoding();

		if ( 'complete' === $classification && 'accepted' !== $media ) {
			$classification = 'media';
		}
		if ( 'complete' === $classification && ! in_array( $contentCoding, array( 'absent', 'identity' ), true ) ) {
			$classification = 'content-coding';
		}

		return $this->observation( $classification, $status, $redirectCount > 0, $media, $contentCoding );
	}

	/**
	 * Classifies cURL transport, peer, retry, redirect, and status state.
	 *
	 * @param int    $errorNumber  cURL error number.
	 * @param int    $status       HTTP response status.
	 * @param string $primaryIp    Connected peer text.
	 * @param int    $redirectCount Followed redirect count.
	 * @return string Stable transfer classification.
	 */
	private function classifyTransfer( int $errorNumber, int $status, string $primaryIp, int $redirectCount ): string {
		if ( 1 < $this->afterSendCount || 1 < $this->requestCount ) {
			return 'retry';
		}
		if ( null !== $this->abortClassification ) {
			return $this->abortClassification;
		}

		if ( 0 !== $errorNumber ) {
			if ( 100 <= $status && 200 > $status ) {
				return 'status';
			}
			if ( CURLE_OPERATION_TIMEDOUT === $errorNumber ) {
				return 'timeout';
			}
			if ( in_array( $errorNumber, $this->tlsErrorNumbers(), true ) ) {
				return 'tls';
			}
			if ( CURLE_PARTIAL_FILE === $errorNumber || CURLE_WRITE_ERROR === $errorNumber ) {
				return $this->declaredBodyExceedsLimit() ? 'body-bytes' : 'truncated';
			}
			if ( CURLE_GOT_NOTHING === $errorNumber ) {
				return 0 === $status ? 'truncated' : 'status';
			}
			if ( defined( 'CURLE_BAD_CONTENT_ENCODING' ) && CURLE_BAD_CONTENT_ENCODING === $errorNumber ) {
				return 'content-coding';
			}

			return 'connect';
		}

		$binary = inet_pton( $primaryIp );
		if (
			! $this->peerMatched
			|| false === $binary
			|| ! isset( $this->screenedBinary[ bin2hex( $binary ) ] )
		) {
			return 'peer';
		}
		if ( ! $this->tlsHostnameVerified ) {
			return 'tls';
		}
		if (
			0 < $redirectCount
			|| ( 300 <= $status && 400 > $status && array() !== ( $this->headers['location'] ?? array() ) )
		) {
			return 'redirect';
		}
		if ( 200 !== $status ) {
			return 'status';
		}
		if ( $this->declaredBodyExceedsLimit() ) {
			return 'body-bytes';
		}
		if ( 1 !== $this->requestCount ) {
			return 'retry';
		}

		return 'complete';
	}

	/**
	 * Classifies one exact JSON or JSON-suffix media type.
	 */
	private function classifyMediaType(): string {
		$values = $this->headers['content-type'] ?? array();
		if ( array() === $values ) {
			return 'missing';
		}
		if ( 1 !== count( $values ) ) {
			return 'ambiguous';
		}

		$value     = trim( $values[0] );
		$token     = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
		$quoted    = '"(?:[^"\\\\\\r\\n]|\\\\.)*"';
		$parameter = ';[ \\t]*' . $token . '[ \\t]*=[ \\t]*(?:' . $token . '|' . $quoted . ')[ \\t]*';
		$pattern   = '/\\Aapplication\\/(?:json|' . $token . '\\+json)[ \\t]*(?:' . $parameter . ')*\\z/iD';

		return 1 === preg_match( $pattern, $value ) ? 'accepted' : 'wrong';
	}

	/**
	 * Classifies absent or explicit identity content coding.
	 */
	private function classifyContentCoding(): string {
		$values = $this->headers['content-encoding'] ?? array();
		if ( array() === $values ) {
			return 'absent';
		}
		if ( 1 !== count( $values ) ) {
			return 'ambiguous';
		}

		return 'identity' === strtolower( trim( $values[0] ) ) ? 'identity' : 'unsupported';
	}

	/**
	 * Detects an exact numeric Content-Length above the body limit.
	 */
	private function declaredBodyExceedsLimit(): bool {
		$values = $this->headers['content-length'] ?? array();
		if ( 1 !== count( $values ) || 1 !== preg_match( '/\\A[0-9]+\\z/D', $values[0] ) ) {
			return false;
		}

		$maximum = $this->intPolicyValue( 'max_body_bytes', 5120 );
		return strlen( $values[0] ) > strlen( (string) $maximum )
			|| ( strlen( $values[0] ) === strlen( (string) $maximum ) && strcmp( $values[0], (string) $maximum ) > 0 );
	}

	/**
	 * Returns available cURL TLS-verification error numbers.
	 *
	 * @return list<int> TLS error numbers.
	 */
	private function tlsErrorNumbers(): array {
		$names   = array(
			'CURLE_SSL_CONNECT_ERROR',
			'CURLE_PEER_FAILED_VERIFICATION',
			'CURLE_SSL_CACERT',
			'CURLE_SSL_CERTPROBLEM',
			'CURLE_SSL_CACERT_BADFILE',
		);
		$numbers = array();
		foreach ( $names as $name ) {
			if ( defined( $name ) ) {
				$value = constant( $name );
				if ( is_int( $value ) ) {
					$numbers[] = $value;
				}
			}
		}

		return array_values( array_unique( $numbers ) );
	}

	/**
	 * Creates the fixed observation and retains representation only on success.
	 *
	 * @param string   $classification       Stable fetch classification.
	 * @param int|null $statusCode           HTTP response status.
	 * @param bool     $redirectFollowed     Whether cURL followed a redirect.
	 * @param string   $mediaClassification  Media-type classification.
	 * @param string   $contentCoding        Content-coding classification.
	 * @return array<string, mixed> Fixed bounded observation.
	 */
	private function observation(
		string $classification,
		?int $statusCode = null,
		bool $redirectFollowed = false,
		string $mediaClassification = 'unavailable',
		string $contentCoding = 'unavailable'
	): array {
		$elapsed = 0;
		if ( 0 < $this->startedNanoseconds ) {
			$elapsed = max( 0, (int) floor( ( hrtime( true ) - $this->startedNanoseconds ) / 1_000_000 ) );
		}

		$accepted = 'complete' === $classification;

		return array(
			'classification'        => $classification,
			'status_code'           => $statusCode,
			'body'                  => $accepted ? $this->body : '',
			'headers'               => $accepted ? $this->headers : array(),
			'body_bytes'            => $this->bodyBytes,
			'header_bytes'          => $this->headerBytes,
			'header_fields'         => $this->headerFields,
			'elapsed_ms'            => $elapsed,
			'request_count'         => $this->requestCount,
			'redirect_followed'     => $redirectFollowed,
			'peer_matched'          => $this->peerMatched,
			'tls_hostname_verified' => $this->tlsHostnameVerified,
			'media_classification'  => $mediaClassification,
			'content_coding'        => $contentCoding,
		);
	}

	/**
	 * Returns one original-host cURL resolve entry containing the full set.
	 */
	private function resolveEntry(): string {
		$host      = null !== $this->identifier ? $this->identifier->host() : '';
		$addresses = array_map(
			static fn ( string $address ): string => str_contains( $address, ':' ) ? '[' . $address . ']' : $address,
			$this->screenedAddresses
		);

		return $host . ':443:' . implode( ',', $addresses );
	}

	/**
	 * Converts textual addresses into exact binary-comparison keys.
	 *
	 * @param array $addresses Text addresses.
	 * @return array<string, string> Binary-keyed address set.
	 * @phpstan-param list<string> $addresses
	 */
	private function binaryAddressSet( array $addresses ): array {
		$result = array();
		foreach ( $addresses as $address ) {
			$binary = inet_pton( $address );
			if ( false !== $binary ) {
				$result[ bin2hex( $binary ) ] = $address;
			}
		}

		return $result;
	}

	/**
	 * Returns the explicit proof CA or WordPress CA bundle.
	 */
	private function certificateAuthorityFile(): ?string {
		if ( null !== $this->caFile && '' !== $this->caFile ) {
			return $this->caFile;
		}

		$environment = getenv( 'P3_FIXTURE_CA_FILE' );
		if ( is_string( $environment ) && '' !== $environment ) {
			return $environment;
		}

		if ( defined( 'ABSPATH' ) && defined( 'WPINC' ) ) {
			$include = constant( 'WPINC' );
			if ( is_string( $include ) ) {
				return ABSPATH . $include . '/certificates/ca-bundle.crt';
			}
		}

		return null;
	}

	/**
	 * Checks exact byte identity against the active request URL.
	 *
	 * @param string $url Candidate request URL.
	 */
	private function isExactActiveUrl( string $url ): bool {
		return $this->active && null !== $this->identifier && $this->identifier->fetchUrl() === $url;
	}

	/**
	 * Returns one integer policy value with its fail-safe default.
	 *
	 * @param string $name     Policy key.
	 * @param int    $fallback Fail-safe value.
	 */
	private function intPolicyValue( string $name, int $fallback ): int {
		$value = $this->policy[ $name ] ?? null;
		return is_int( $value ) && 0 <= $value ? $value : $fallback;
	}

	/**
	 * Returns one string policy value with its fail-safe default.
	 *
	 * @param string $name     Policy key.
	 * @param string $fallback Fail-safe value.
	 */
	private function stringPolicyValue( string $name, string $fallback ): string {
		$value = $this->policy[ $name ] ?? null;
		return is_string( $value ) ? $value : $fallback;
	}

	/**
	 * Resets all per-request capture state before hook installation.
	 */
	private function resetState(): void {
		$this->handle              = null;
		$this->body                = '';
		$this->bodyBytes           = 0;
		$this->headerBytes         = 0;
		$this->headerFields        = 0;
		$this->capturedStatusCode  = 0;
		$this->headers             = array();
		$this->abortClassification = null;
		$this->requestCount        = 0;
		$this->afterSendCount      = 0;
		$this->peerMatched         = false;
		$this->tlsHostnameVerified = false;
		$this->startedNanoseconds  = 0;
	}
}

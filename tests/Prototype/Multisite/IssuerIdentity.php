<?php
/**
 * Disposable Slice 0 site issuer identity boundary.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\Multisite;

/**
 * Constructs an issuer identity from an explicit WordPress site locator.
 *
 * @since 0.1.0
 */
final class IssuerIdentity {

	/**
	 * The WordPress site locator associated with the issuer.
	 *
	 * @since 0.1.0
	 *
	 * @var int
	 */
	private int $siteId;

	/**
	 * The opaque canonical issuer URL.
	 *
	 * @since 0.1.0
	 *
	 * @var string
	 */
	private string $issuer;

	/**
	 * Creates an issuer identity.
	 *
	 * @since 0.1.0
	 *
	 * @param int    $siteId The WordPress site locator.
	 * @param string $issuer The opaque canonical issuer URL.
	 */
	private function __construct( int $siteId, string $issuer ) {
		$this->siteId = $siteId;
		$this->issuer = $issuer;
	}

	/**
	 * Constructs the canonical identity for one explicit WordPress site.
	 *
	 * @since 0.1.0
	 *
	 * @param int $siteId The WordPress site locator.
	 * @return self The site issuer identity.
	 */
	public static function forSite( int $siteId ): self {
		return new self( $siteId, untrailingslashit( get_home_url( $siteId ) ) );
	}

	/**
	 * Constructs the canonical identity for the current WordPress site.
	 *
	 * @since 0.1.0
	 *
	 * @return self The current site issuer identity.
	 */
	public static function forCurrentSite(): self {
		return self::forSite( get_current_blog_id() );
	}

	/**
	 * Returns the non-identity WordPress site locator.
	 *
	 * @since 0.1.0
	 *
	 * @return int The WordPress site locator.
	 */
	public function siteId(): int {
		return $this->siteId;
	}

	/**
	 * Returns the opaque canonical issuer URL.
	 *
	 * @since 0.1.0
	 *
	 * @return string The issuer URL.
	 */
	public function issuer(): string {
		return $this->issuer;
	}
}

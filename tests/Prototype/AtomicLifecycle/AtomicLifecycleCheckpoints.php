<?php
/**
 * Disposable Slice 0 atomic-lifecycle transition checkpoints.
 *
 * @package GalatanOvidiu\Charter
 */

declare(strict_types=1);

namespace GalatanOvidiu\Charter\Tests\Prototype\AtomicLifecycle;

/**
 * Names the fixed coordinator and fault-injection checkpoints.
 *
 * @since 0.1.0
 */
final class AtomicLifecycleCheckpoints {

	public const BEFORE_CLAIM = 'before_claim';

	public const AFTER_AGGREGATE_LOCK = 'after_aggregate_lock';

	public const AFTER_CLAIM = 'after_claim';

	public const AFTER_DESCENDANT = 'after_descendant';

	public const DURING_REVOKE = 'during_revoke';

	public const BEFORE_COMMIT = 'before_commit';

	public const AFTER_COMMIT = 'after_commit';

	public const AFTER_FIRST_SENTINEL_LOCK = 'after_first_sentinel_lock';

	public const AFTER_CONNECTION_MUTATION = 'after_connection_mutation';

	/**
	 * This class contains constants only.
	 */
	private function __construct() {
	}
}

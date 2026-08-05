<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Publishes a committed role, permission, or assignment mutation.
 */
final class RbacChanged implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create the RBAC event.
     *
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly string $entityType,
        public readonly string $entityId,
        public readonly string $operation,
        public readonly array $payload = [],
    ) {}
}

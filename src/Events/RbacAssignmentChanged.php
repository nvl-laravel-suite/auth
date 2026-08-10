<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Publishes every committed package-owned principal access assignment.
 */
final class RbacAssignmentChanged implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create the principal access assignment event.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $principalId,
        public readonly string $operation,
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $metadata = [],
    ) {}
}

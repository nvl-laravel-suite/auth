<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use JsonSerializable;

/**
 * Reports deterministic permission and role synchronization counts.
 */
final readonly class RbacSynchronizationResult implements JsonSerializable
{
    /**
     * Create an RBAC synchronization report.
     */
    public function __construct(
        public int $permissionsCreated,
        public int $rolesSynchronized,
        public string $guard,
    ) {}

    /**
     * Return the stable public report representation.
     *
     * @return array{permissions_created: int, roles_synchronized: int, guard: string}
     */
    public function jsonSerialize(): array
    {
        return [
            'permissions_created' => $this->permissionsCreated,
            'roles_synchronized' => $this->rolesSynchronized,
            'guard' => $this->guard,
        ];
    }
}

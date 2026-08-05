<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

/**
 * Reports bounded RBAC catalog and assignment aggregates.
 */
final readonly class RbacAnalytics
{
    /**
     * Create the analytics result.
     *
     * @param  list<array{id: string, name: string, users_count: int, permissions_count: int}>  $largestRoles
     */
    public function __construct(
        public int $roles,
        public int $permissions,
        public int $roleAssignments,
        public int $directPermissionAssignments,
        public int $unassignedRoles,
        public array $largestRoles,
    ) {}
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Locates host principals and applies Spatie Permission assignments to them.
 */
interface RbacPrincipalAccess
{
    /**
     * Resolve a host principal instance or identifier.
     */
    public function find(Authenticatable|string $principal): Authenticatable;

    /**
     * Return the principal's persistent identifier.
     */
    public function identifier(Authenticatable $principal): string;

    /**
     * Return the principal's database connection name.
     */
    public function connectionName(Authenticatable $principal): ?string;

    /**
     * Assign roles and direct permissions without replacing existing access.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function assign(Authenticatable $principal, array $roles, array $permissions): void;

    /**
     * Replace the principal's role assignment.
     *
     * @param  list<string>  $roles
     */
    public function syncRoles(Authenticatable $principal, array $roles): void;

    /**
     * Replace the principal's direct permission assignment.
     *
     * @param  list<string>  $permissions
     */
    public function syncPermissions(Authenticatable $principal, array $permissions): void;

    /**
     * Reload the principal and requested RBAC relations.
     *
     * @param  list<string>  $relations
     */
    public function refresh(Authenticatable $principal, array $relations = []): Authenticatable;
}

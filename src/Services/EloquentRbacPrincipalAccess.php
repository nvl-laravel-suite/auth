<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

/**
 * Applies RBAC to a configured Eloquent principal without requiring package principal management.
 */
final readonly class EloquentRbacPrincipalAccess implements RbacPrincipalAccess
{
    /**
     * Resolve a configured host principal instance or identifier.
     */
    public function find(Authenticatable|string $principal): Authenticatable
    {
        if ($principal instanceof Authenticatable) {
            return $this->assertCompatible($principal);
        }

        $class = $this->principalClass();
        $resolved = $class::query()->findOrFail($principal);

        if (! $resolved instanceof Authenticatable) {
            throw AuthException::invalidConfiguration('The configured RBAC principal must implement Authenticatable.');
        }

        return $this->assertCompatible($resolved);
    }

    /**
     * Return the principal's persistent identifier.
     */
    public function identifier(Authenticatable $principal): string
    {
        $identifier = $principal->getAuthIdentifier();

        if (! is_string($identifier) && ! is_int($identifier)) {
            throw AuthException::invalidConfiguration('RBAC principals must expose a string-compatible identifier.');
        }

        return (string) $identifier;
    }

    /**
     * Return the principal's database connection name.
     */
    public function connectionName(Authenticatable $principal): ?string
    {
        $principal = $this->assertCompatible($principal);

        return $principal->getConnection()->getName();
    }

    /**
     * Assign roles and direct permissions without replacing existing access.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function assign(Authenticatable $principal, array $roles, array $permissions): void
    {
        $principal = $this->assertCompatible($principal);

        if ($roles !== []) {
            $principal->assignRole($roles);
        }

        if ($permissions !== []) {
            $principal->givePermissionTo($permissions);
        }
    }

    /**
     * Replace the principal's role assignment.
     *
     * @param  list<string>  $roles
     */
    public function syncRoles(Authenticatable $principal, array $roles): void
    {
        $this->assertCompatible($principal)->syncRoles($roles);
    }

    /**
     * Replace the principal's direct permission assignment.
     *
     * @param  list<string>  $permissions
     */
    public function syncPermissions(Authenticatable $principal, array $permissions): void
    {
        $this->assertCompatible($principal)->syncPermissions($permissions);
    }

    /**
     * Reload the principal and requested RBAC relations.
     *
     * @param  list<string>  $relations
     */
    public function refresh(Authenticatable $principal, array $relations = []): Authenticatable
    {
        $principal = $this->assertCompatible($principal)->refresh();

        if ($relations !== []) {
            $principal->load($relations);
        }

        return $principal;
    }

    /**
     * Resolve the independently configured RBAC principal model.
     *
     * @return class-string<Model&Authenticatable>
     */
    private function principalClass(): string
    {
        $configured = config('nvl-auth.features.rbac.models.principal');
        $configured = is_string($configured) && trim($configured) !== ''
            ? $configured
            : config('nvl-auth.features.principal_management.models.user', User::class);

        if (! is_string($configured)
            || ! is_a($configured, Model::class, true)
            || ! is_a($configured, Authenticatable::class, true)) {
            throw AuthException::invalidConfiguration(
                'The configured RBAC principal must be an Eloquent Authenticatable model.',
            );
        }

        /** @var class-string<Model&Authenticatable> $configured */
        return $configured;
    }

    /**
     * Require the Spatie Permission model surface used by package assignments.
     *
     * @return Model&Authenticatable
     */
    private function assertCompatible(Authenticatable $principal): Model
    {
        if (! $principal instanceof Model
            || ! method_exists($principal, 'assignRole')
            || ! method_exists($principal, 'givePermissionTo')
            || ! method_exists($principal, 'syncRoles')
            || ! method_exists($principal, 'syncPermissions')) {
            throw AuthException::invalidConfiguration(
                'RBAC principals must be Eloquent Authenticatable models using Spatie Permission HasRoles.',
            );
        }

        return $principal;
    }
}

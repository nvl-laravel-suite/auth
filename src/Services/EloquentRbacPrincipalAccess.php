<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Exceptions\AuthException;
use ReflectionMethod;

/**
 * Applies RBAC to a configured Eloquent principal without requiring package principal management.
 */
final readonly class EloquentRbacPrincipalAccess implements RbacPrincipalAccess
{
    /** Create the configured Eloquent RBAC adapter. */
    public function __construct(private ?AuthModelRegistry $models = null, private ?AuthTenantRbacQueries $tenancy = null) {}

    /**
     * Resolve a configured host principal instance or identifier.
     */
    public function find(Authenticatable|string $principal): Authenticatable
    {
        if ($principal instanceof Authenticatable) {
            $principal = $this->assertCompatible($principal);

            return config('nvl-tenancy.enabled') === true
                ? $this->queries()->assertAssignmentPrincipal($principal)
                : $principal;
        }

        $class = $this->principalClass();
        $resolved = $class::query()->findOrFail($principal);

        if (! $resolved instanceof Authenticatable) {
            throw AuthException::invalidConfiguration('The configured RBAC principal must implement Authenticatable.');
        }

        $resolved = $this->assertCompatible($resolved);

        return config('nvl-tenancy.enabled') === true
            ? $this->queries()->assertAssignmentPrincipal($resolved)
            : $resolved;
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
        $principal = $this->assignmentPrincipal($principal);

        if ($roles !== []) {
            $this->invokeAssignment($principal, 'assignRole', $roles);
        }

        if ($permissions !== []) {
            $this->invokeAssignment($principal, 'givePermissionTo', $permissions);
        }
    }

    /**
     * Replace the principal's role assignment.
     *
     * @param  list<string>  $roles
     */
    public function syncRoles(Authenticatable $principal, array $roles): void
    {
        $this->invokeAssignment($this->assignmentPrincipal($principal), 'syncRoles', $roles);
    }

    /**
     * Replace the principal's direct permission assignment.
     *
     * @param  list<string>  $permissions
     */
    public function syncPermissions(Authenticatable $principal, array $permissions): void
    {
        $this->invokeAssignment($this->assignmentPrincipal($principal), 'syncPermissions', $permissions);
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
        return ($this->models ?? app(AuthModelRegistry::class))->rbacPrincipalClass();
    }

    private function queries(): AuthTenantRbacQueries
    {
        if (! $this->tenancy instanceof AuthTenantRbacQueries) {
            throw AuthException::invalidConfiguration(
                'Tenant RBAC principal access requires the tenant query collaborator.',
            );
        }

        return $this->tenancy;
    }

    /** @return Model&Authenticatable */
    private function assignmentPrincipal(Authenticatable $principal): Model
    {
        $principal = $this->assertCompatible($principal);
        if (config('nvl-tenancy.enabled') === true) {
            $principal = $this->queries()->assertAssignmentPrincipal($principal);
        }

        return $this->assertCompatible($principal);
    }

    /**
     * Invoke the selected public Spatie capability after validating the host model boundary.
     *
     * @param  list<string>  $values
     */
    private function invokeAssignment(Model&Authenticatable $principal, string $method, array $values): void
    {
        $operation = [$principal, $method];
        if (! (new ReflectionMethod($principal, $method))->isPublic() || ! is_callable($operation)) {
            throw AuthException::invalidConfiguration('RBAC principal assignment capabilities must be public callable methods.');
        }
        $operation($values);
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

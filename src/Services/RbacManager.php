<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacAssignmentChanged;
use Nvl\Auth\Exceptions\AuthException;
use Spatie\Permission\PermissionRegistrar;

/**
 * Applies package RBAC payloads through Spatie Permission's configured model trait.
 */
final readonly class RbacManager
{
    /**
     * Create the Spatie Permission integration.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthModelRegistry $models,
        private RbacPrincipalAccess $principals,
        private PermissionRegistrar $registrar,
    ) {}

    /**
     * Assign invitation roles and direct permissions to a configured principal.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function assign(
        Authenticatable $subject,
        array $roles,
        array $permissions,
    ): void {
        if ($roles === [] && $permissions === []) {
            return;
        }

        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);

        $roleClass = $this->models->roleClass();
        $permissionClass = $this->models->permissionClass();
        $connections = [
            $this->principals->connectionName($subject),
            (new $roleClass)->getConnection()->getName(),
            (new $permissionClass)->getConnection()->getName(),
        ];

        if (count(array_unique($connections)) !== 1) {
            throw AuthException::invalidConfiguration(
                'RBAC assignments require principals, roles, and permissions on one database connection.',
            );
        }

        $this->principals->assign($subject, $roles, $permissions);
        $this->registrar->forgetCachedPermissions();
        RbacAssignmentChanged::dispatch(
            $this->principals->identifier($subject),
            'assigned',
            $roles,
            $permissions,
        );
    }

    /**
     * Replace one principal's roles through the common assignment boundary.
     *
     * @param  list<string>  $roles
     * @param  array<string, mixed>  $metadata
     */
    public function syncRoles(Authenticatable $subject, array $roles, array $metadata = []): void
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->principals->syncRoles($subject, $roles);
        $this->registrar->forgetCachedPermissions();
        RbacAssignmentChanged::dispatch(
            $this->principals->identifier($subject),
            'roles_synchronized',
            $roles,
            metadata: $metadata,
        );
    }

    /**
     * Replace one principal's direct permissions through the common assignment boundary.
     *
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function syncPermissions(Authenticatable $subject, array $permissions, array $metadata = []): void
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->principals->syncPermissions($subject, $permissions);
        $this->registrar->forgetCachedPermissions();
        RbacAssignmentChanged::dispatch(
            $this->principals->identifier($subject),
            'permissions_synchronized',
            permissions: $permissions,
            metadata: $metadata,
        );
    }

    /**
     * Reload one principal with requested RBAC relations.
     *
     * @param  list<string>  $relations
     */
    public function refresh(Authenticatable $subject, array $relations = []): Authenticatable
    {
        return $this->principals->refresh($subject, $relations);
    }
}

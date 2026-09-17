<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthTenantRbacQueries;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Shows one permission and its role assignments. */
final readonly class ShowPermissionAction
{
    /** Create the permission read use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
        private AuthTenantRbacQueries $tenancy,
    ) {}

    /** Return one permission. */
    public function execute(Authenticatable $actor, Permission|string $permission): Permission
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');

        $permission = $this->entities->permission($permission);
        if (config('tenancy.enabled') !== true) {
            return $permission->load('roles')->loadCount('users');
        }
        $roles = $this->tenancy->roles()
            ->whereHas('permissions', static fn (Builder $query): Builder => $query->whereKey($permission->id))
            ->get();
        $permission->setRelation('roles', $roles);

        return $permission->loadCount('users');
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Shows one role and its canonical permission assignment. */
final readonly class ShowRoleAction
{
    /** Create the role read use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
    ) {}

    /** Return one role. */
    public function execute(Authenticatable $actor, Role|string $role): Role
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');

        return $this->entities->role($role)->load(['parent', 'children', 'permissions'])->loadCount('users');
    }
}

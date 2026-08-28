<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Resolves bounded mixed permission IDs and names into stable projections. */
final readonly class ResolvePermissionIdentifiersAction
{
    /** Create the permission identifier resolution use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
    ) {}

    /**
     * Resolve permission identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, PermissionOptionData>
     */
    public function execute(Authenticatable $actor, array $identifiers): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');

        return $this->entities
            ->permissionsByIdentifiers($identifiers)
            ->map(static fn (Permission $permission): PermissionOptionData => PermissionOptionData::fromModel($permission));
    }
}

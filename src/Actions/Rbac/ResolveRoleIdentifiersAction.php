<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\RoleOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacEntityLocator;

/** Resolves bounded mixed role IDs and names into stable projections. */
final readonly class ResolveRoleIdentifiersAction
{
    /** Create the role identifier resolution use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacEntityLocator $entities,
    ) {}

    /**
     * Resolve role identifiers in caller order without exposing models.
     *
     * @param  list<string>  $identifiers
     * @return Collection<int, RoleOptionData>
     */
    public function execute(Authenticatable $actor, array $identifiers): Collection
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');

        return $this->entities
            ->rolesByIdentifiers($identifiers)
            ->map(static fn (Role $role): RoleOptionData => RoleOptionData::fromModel($role));
    }
}

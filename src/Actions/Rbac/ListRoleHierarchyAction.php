<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RoleHierarchy;

/** Renders the complete package role hierarchy. */
final readonly class ListRoleHierarchyAction
{
    /** Create the hierarchy read use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RoleHierarchy $hierarchy,
    ) {}

    /** @return list<array{id: string, name: string, display_name: string|null, priority: int, user_count: int, children: list<mixed>}> */
    public function execute(Authenticatable $actor): array
    {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $class = $this->models->roleClass();
        $roles = $class::query()->withCount('users')->orderByDesc('priority')->orderBy('name')->get();

        return $this->hierarchy->tree($roles);
    }
}

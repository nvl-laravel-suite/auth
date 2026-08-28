<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacConsumerLimits;

/** Lists bounded permission options for consumer-owned selectors. */
final readonly class ListPermissionOptionsAction
{
    /** Create the permission option listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RbacConsumerLimits $limits,
    ) {}

    /**
     * Return minimal permission projections without exposing Eloquent models.
     *
     * @return Collection<int, PermissionOptionData>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?string $group = null,
        ?int $limit = null,
    ): Collection {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $search = $this->normalizedSearch($search);
        $group = $this->normalizedGroup($group);
        $class = $this->models->permissionClass();
        $query = $class::query()->select([
            'id',
            'name',
            'display_name',
            'description',
            'group',
        ]);

        if ($search !== null) {
            $term = "%{$search}%";
            $query->where(static function ($searchQuery) use ($term): void {
                $searchQuery
                    ->where('name', 'like', $term)
                    ->orWhere('display_name', 'like', $term)
                    ->orWhere('description', 'like', $term)
                    ->orWhere('group', 'like', $term);
            });
        }

        if ($group !== null) {
            $this->applyGroupFilter($query, $group);
        }

        return $query
            ->orderBy('group')
            ->orderBy('name')
            ->orderBy('id')
            ->limit($this->limits->permissionOptionLimit($limit))
            ->get()
            ->map(static fn (Permission $permission): PermissionOptionData => PermissionOptionData::fromModel($permission));
    }

    /** Normalize and constrain an untrusted selector search. */
    private function normalizedSearch(?string $search): ?string
    {
        $search = trim((string) $search);

        if (mb_strlen($search) > 160) {
            throw new AuthException(
                'invalid_permission_search',
                'Permission search may not exceed 160 characters.',
            );
        }

        return $search !== '' ? $search : null;
    }

    /** Normalize and constrain an exact permission group filter. */
    private function normalizedGroup(?string $group): ?string
    {
        $group = trim((string) $group);

        if (mb_strlen($group) > 120) {
            throw new AuthException(
                'invalid_permission_group',
                'Permission group may not exceed 120 characters.',
            );
        }

        return $group !== '' ? $group : null;
    }

    /**
     * Apply an exact filter using the same general-group normalization as DTOs.
     *
     * @param  Builder<Permission>  $query
     */
    private function applyGroupFilter(Builder $query, string $group): void
    {
        if ($group !== 'general') {
            $query->where('group', $group);

            return;
        }

        $query->where(static function ($groupQuery): void {
            $groupQuery
                ->where('group', 'general')
                ->orWhereNull('group')
                ->orWhere('group', '');
        });
    }
}

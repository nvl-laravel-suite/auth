<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Memberships;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Tenancy\Services\TenantBoundary;

/** Lists only membership rows inside the active tenant. */
final readonly class ListMembershipsAction
{
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private TenantBoundary $boundary,
        private AuthConfiguration $configuration,
    ) {}

    /** @return LengthAwarePaginator<int, TenantMembership> */
    public function execute(Authenticatable $actor, ?string $search = null, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::Memberships, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.memberships.viewAny');
        if ($search !== null && mb_strlen($search) > 191) {
            throw new AuthException('invalid_membership_filter', 'Membership search is too long.', 422);
        }
        $query = $this->boundary->query(TenantMembership::query(), 'auth.memberships');
        if ($search !== null && trim($search) !== '') {
            $term = '%'.trim($search).'%';
            $query->where(static function (Builder $builder) use ($term): void {
                $builder->where('subject_id', 'like', $term)->orWhere('subject_type', 'like', $term);
            });
        }
        $maximum = $this->configuration->positiveInteger('features.memberships.settings.maximum_per_page', 100);

        return $query->orderBy('created_at')->paginate(max(1, min($perPage, $maximum)));
    }
}

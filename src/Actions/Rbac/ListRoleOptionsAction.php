<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\RoleOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacConsumerLimits;
use Nvl\Auth\Services\RbacOptionReadService;

/** Lists bounded role options for consumer-owned selectors. */
final readonly class ListRoleOptionsAction
{
    /** Create the role option listing use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacConsumerLimits $limits,
        private RbacOptionReadService $options,
    ) {}

    /**
     * Return minimal role projections without exposing Eloquent models.
     *
     * @return Collection<int, RoleOptionData>
     */
    public function execute(
        Authenticatable $actor,
        ?string $search = null,
        ?int $limit = null,
    ): Collection {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $search = $this->normalizedSearch($search);

        return $this->options->roles($search, $this->limits->roleOptionLimit($limit));
    }

    /** Normalize and constrain an untrusted selector search. */
    private function normalizedSearch(?string $search): ?string
    {
        $search = trim((string) $search);

        if (mb_strlen($search) > 160) {
            throw new AuthException(
                'invalid_role_search',
                'Role search may not exceed 160 characters.',
            );
        }

        return $search !== '' ? $search : null;
    }
}

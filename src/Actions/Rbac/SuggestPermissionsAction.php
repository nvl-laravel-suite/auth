<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Nvl\Auth\Data\Display\PermissionOptionData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacConsumerLimits;
use Nvl\Auth\Services\RbacOptionReadService;

/** Resolves bounded permission suggestions for typeahead consumers. */
final readonly class SuggestPermissionsAction
{
    /** Create the permission suggestion use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private RbacConsumerLimits $limits,
        private RbacOptionReadService $options,
    ) {}

    /**
     * Return defaults for an empty search and no results for a one-character search.
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
        $search = trim((string) $search);
        $group = $this->normalizedGroup($group);

        if (mb_strlen($search) > 160) {
            throw new AuthException(
                'invalid_permission_search',
                'Permission search may not exceed 160 characters.',
            );
        }

        if ($search === '') {
            return $this->options->permissions(
                null,
                $group,
                $this->limits->permissionOptionLimit($limit),
            );
        }

        if (mb_strlen($search) === 1) {
            return new Collection;
        }

        return $this->options->permissions(
            $search,
            $group,
            $this->limits->permissionOptionLimit($limit),
        );
    }

    /** Normalize and constrain an exact permission group filter. */
    private function normalizedGroup(?string $group): ?string
    {
        $rawGroup = (string) $group;

        if (mb_strlen($rawGroup) > 120) {
            throw new AuthException(
                'invalid_permission_group',
                'Permission group may not exceed 120 characters.',
            );
        }

        return PermissionOptionData::normalizeNullableGroup($rawGroup);
    }
}

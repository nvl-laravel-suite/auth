<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Rbac;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Nvl\Auth\Data\Display\RoleNameAvailabilityData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;

/** Checks one canonical role name without exposing role models. */
final readonly class CheckRoleNameAvailabilityAction
{
    /** Create the role availability use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private AuthConfiguration $configuration,
    ) {}

    /** Return availability within the configured RBAC guard. */
    public function execute(
        Authenticatable $actor,
        string $name,
        ?string $exceptId = null,
    ): RoleNameAvailabilityData {
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.rbac.view');
        $name = trim($name);

        if ($name === '' || mb_strlen($name) > 160) {
            throw new AuthException(
                'invalid_role_name',
                'Role names must contain between one and 160 characters.',
            );
        }

        if ($exceptId !== null) {
            $exceptId = trim($exceptId);

            if (! Str::isUuid($exceptId)) {
                throw new AuthException(
                    'invalid_role_identifier',
                    'Excluded role identifiers must be UUIDs.',
                );
            }
        }

        $class = $this->models->roleClass();
        $guard = $this->configuration->string('features.rbac.settings.guard', 'web');
        $conflictingRoleId = $class::query()
            ->where('guard_name', $guard)
            ->where('name', $name)
            ->when($exceptId !== null, static fn ($query) => $query->whereKeyNot($exceptId))
            ->value('id');
        $conflictingRoleId = is_string($conflictingRoleId) ? $conflictingRoleId : null;

        return new RoleNameAvailabilityData(
            name: $name,
            available: $conflictingRoleId === null,
            conflictingRoleId: $conflictingRoleId,
        );
    }
}

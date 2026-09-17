<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\UserLocator;

/**
 * Returns the authenticated package principal profile.
 */
final readonly class ShowProfileAction
{
    /** Create the profile read use case. */
    public function __construct(
        private FeatureGate $features,
        private UserLocator $users,
        private AuthOperationBoundary $operations,
    ) {}

    /** Return the authenticated principal. */
    public function execute(Authenticatable $subject): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->operations->central(AuthIdentityOperation::Profile, $subject);

        return $this->users->authenticated($subject)->load(['roles', 'permissions']);
    }
}

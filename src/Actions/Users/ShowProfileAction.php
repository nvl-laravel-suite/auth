<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\User;
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
    ) {}

    /** Return the authenticated principal. */
    public function execute(Authenticatable $subject): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);

        return $this->users->authenticated($subject)->load(['roles', 'permissions']);
    }
}

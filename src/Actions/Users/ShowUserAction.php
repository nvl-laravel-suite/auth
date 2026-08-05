<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;

/**
 * Shows one package principal and its effective access assignments.
 */
final readonly class ShowUserAction
{
    /** Create the principal read use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
    ) {}

    /** Return one principal. */
    public function execute(Authenticatable $actor, User|string $user): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Read);
        $this->authorization->authorize($actor, 'nvl-auth.users.view');

        return $this->users->find($user, true)->load(['roles', 'permissions']);
    }
}

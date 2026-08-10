<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Restores one soft-deleted package principal.
 */
final readonly class RestoreUserAction
{
    /** Create the restoration use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Restore one principal without silently re-enabling it. */
    public function execute(Authenticatable $actor, User|string $user): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.users.restore');
        $user = $this->users->find($user, true);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $user): User {
            $user->restore();
            $this->audits->record('user.restored', subject: SubjectReference::fromAuthenticatable($user), actor: $actor);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'restored');

            return $user->refresh();
        }, 3);
    }
}

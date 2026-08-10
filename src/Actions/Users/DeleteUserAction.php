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
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Soft deletes one principal while revoking active API tokens.
 */
final readonly class DeleteUserAction
{
    /** Create the deletion use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Soft delete one principal. */
    public function execute(Authenticatable $actor, User|string $user): bool
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $this->authorization->authorize($actor, 'nvl-auth.users.delete');
        $user = $this->users->find($user);

        if ($actor->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_delete_forbidden', 'You cannot delete your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $user): bool {
            $reference = SubjectReference::fromAuthenticatable($user);
            $user->tokens()->delete();
            $deleted = (bool) $user->delete();
            $this->audits->record('user.deleted', subject: $reference, actor: $actor);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'deleted');

            return $deleted;
        }, 3);
    }
}

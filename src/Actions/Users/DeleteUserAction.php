<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Soft deletes one principal while revoking active API tokens.
 */
final readonly class DeleteUserAction
{
    /** Create the deletion use case. */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
        private PrincipalSessionContainment $sessions,
    ) {}

    /** Soft delete one principal. */
    public function execute(Authenticatable|SystemMutationContext $authority, User|string $user): bool
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.users.delete', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user);

        if ($authority instanceof Authenticatable && $authority->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_delete_forbidden', 'You cannot delete your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $metadata, $user): bool {
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->sessions->contain($user, 'deleted', $context);
            $deleted = (bool) $user->delete();
            $this->audits->record('user.deleted', subject: $reference, actor: $actor, metadata: $metadata);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'deleted', $metadata);

            return $deleted;
        }, 3);
    }
}

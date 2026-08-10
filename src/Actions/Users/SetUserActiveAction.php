<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
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
 * Enables or disables one package principal and contains active tokens on disable.
 */
final readonly class SetUserActiveAction
{
    /** Create the activation use case. */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
        private PrincipalSessionContainment $sessions,
    ) {}

    /** Persist the principal activation state. */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        User|string $user,
        UpdateUserStatusData $data,
    ): User {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $actor = $this->authorization->authorize($authority, 'nvl-auth.users.update', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user);

        if (! $data->active
            && $authority instanceof Authenticatable
            && $authority->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_disable_forbidden', 'You cannot disable your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $data, $metadata, $user): User {
            $user->update($this->attributes->map($data->toArray()));

            if (! $data->active) {
                $this->sessions->contain($user, 'disabled', $context);
            }

            $operation = $data->active ? 'enabled' : 'disabled';
            $this->audits->record(
                "user.{$operation}",
                subject: SubjectReference::fromAuthenticatable($user),
                actor: $actor,
                metadata: $metadata,
            );
            PrincipalChanged::dispatch($this->attributes->identifier($user), $operation, $metadata);

            return $user->refresh();
        }, 3);
    }
}

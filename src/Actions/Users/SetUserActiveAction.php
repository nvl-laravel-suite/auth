<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Enables or disables one package principal and contains active tokens on disable.
 */
final readonly class SetUserActiveAction
{
    /** Create the activation use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Persist the principal activation state. */
    public function execute(Authenticatable $actor, User|string $user, bool $active): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.users.update');
        $user = $this->users->find($user);

        if (! $active && $actor->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_disable_forbidden', 'You cannot disable your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($active, $actor, $user): User {
            $user->forceFill($this->attributes->map([
                PrincipalAttribute::Active->value => $active,
            ]))->save();

            if (! $active) {
                $user->tokens()->delete();
            }

            $operation = $active ? 'enabled' : 'disabled';
            $this->audits->record("user.{$operation}", subject: SubjectReference::fromAuthenticatable($user), actor: $actor);
            PrincipalChanged::dispatch($this->attributes->identifier($user), $operation);

            return $user->refresh();
        }, 3);
    }
}

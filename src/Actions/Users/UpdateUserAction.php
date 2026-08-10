<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\UpdateUserData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Updates one package principal without changing its access assignment.
 */
final readonly class UpdateUserAction
{
    /** Create the principal update use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
    ) {}

    /** Persist a partial principal mutation. */
    public function execute(Authenticatable $actor, User|string $user, UpdateUserData $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.users.update');
        $user = $this->users->find($user, true);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $data, $user): User {
            $attributes = $data->toArray();
            $user->update($this->attributes->map($attributes));
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('user.updated', subject: $reference, actor: $actor, metadata: [
                'attributes' => array_keys($attributes),
            ]);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'updated', ['attributes' => array_keys($attributes)]);

            return $user->refresh()->load(['roles', 'permissions']);
        }, 3);
    }
}

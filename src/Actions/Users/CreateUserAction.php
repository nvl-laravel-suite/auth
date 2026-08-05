<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\RbacManager;
use Nvl\Auth\ValueObjects\CreateUserData;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Creates one complete package principal.
 */
final readonly class CreateUserAction
{
    /** Create the principal creation use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private AuthModelRegistry $models,
        private RbacManager $rbac,
        private AuthAuditRecorder $audits,
    ) {}

    /** Persist a principal and optional RBAC assignment atomically. */
    public function execute(Authenticatable $actor, CreateUserData $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Issue);
        $this->authorization->authorize($actor, 'nvl-auth.users.create');

        if ($data->roles !== [] || $data->permissions !== []) {
            $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
            $this->authorization->authorize($actor, 'nvl-auth.users.manageAccess');
        }

        $class = $this->models->userClass();
        $connection = (new $class)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $class, $data): User {
            $user = $class::query()->create([
                'name' => trim($data->name),
                'email' => mb_strtolower(trim($data->email)),
                'password' => $data->password,
                'is_active' => $data->active,
                'locale' => $data->locale,
                'timezone' => $data->timezone,
                'profile' => $data->profile,
                'preferences' => $data->preferences,
                'email_verified_at' => $data->emailVerified ? now() : null,
            ]);
            $this->rbac->assign($user, $data->roles, $data->permissions);
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('user.created', subject: $reference, actor: $actor);
            PrincipalChanged::dispatch($user->id, 'created', ['email' => $user->email]);

            return $user->refresh()->load(['roles', 'permissions']);
        }, 3);
    }
}

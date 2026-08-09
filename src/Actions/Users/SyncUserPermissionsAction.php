<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\RbacChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Replaces one principal's direct permission assignment.
 */
final readonly class SyncUserPermissionsAction
{
    /** Create the permission assignment use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Synchronize direct permission names atomically.
     *
     * @param  list<string>  $permissions
     */
    public function execute(Authenticatable $actor, User|string $user, array $permissions): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
        $this->authorization->authorize($actor, 'nvl-auth.users.manageAccess');
        $this->assertValidNames($permissions, 250, 'permissions');
        $user = $this->users->find($user);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $permissions, $user): User {
            $user->syncPermissions($permissions);
            $this->audits->record('user.permissions_synchronized', subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: [
                'permissions' => $permissions,
            ]);
            RbacChanged::dispatch('user', $user->id, 'permissions_synchronized', ['permissions' => $permissions]);

            return $user->refresh()->load('permissions');
        }, 3);
    }

    /** @param list<string> $names */
    private function assertValidNames(array $names, int $maximum, string $field): void
    {
        if (count($names) > $maximum) {
            throw new AuthException('invalid_access_assignment', "User {$field} must be a list of at most {$maximum} names.", 422);
        }

        $seen = [];

        foreach ($names as $name) {
            if (trim($name) === '' || mb_strlen($name) > 160) {
                throw new AuthException('invalid_access_assignment', "User {$field} names must contain between one and 160 characters.", 422);
            }

            if (isset($seen[$name])) {
                throw new AuthException('invalid_access_assignment', "User {$field} names must be distinct.", 422);
            }

            $seen[$name] = true;
        }
    }
}

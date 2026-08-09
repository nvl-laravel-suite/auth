<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Results\BulkUserResult;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\ManagementAuthorizer;
use Nvl\Auth\Services\UserLocator;

/**
 * Applies one bounded principal lifecycle operation atomically.
 */
final readonly class BulkUpdateUsersAction
{
    /** Create the bulk mutation use case. */
    public function __construct(
        private FeatureGate $features,
        private ManagementAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Apply one operation to at most one hundred principals.
     *
     * @param  list<string>  $userIds
     */
    public function execute(
        Authenticatable $actor,
        UserBulkOperation $operation,
        array $userIds,
    ): BulkUserResult {
        $this->features->assertAllowed(
            AuthFeature::PrincipalManagement,
            in_array($operation, [UserBulkOperation::Delete, UserBulkOperation::Restore], true)
                ? FeatureOperation::Revoke
                : FeatureOperation::Update,
        );
        $this->authorization->authorize($actor, match ($operation) {
            UserBulkOperation::Delete => 'nvl-auth.users.delete',
            UserBulkOperation::Restore => 'nvl-auth.users.restore',
            default => 'nvl-auth.users.update',
        });
        if ($userIds === []
            || count($userIds) > 100
            || count(array_filter($userIds, static fn (string $id): bool => ! Str::isUuid($id))) > 0) {
            throw new AuthException('invalid_bulk_selection', 'Bulk operations require between one and one hundred users.', 422);
        }

        $userIds = array_values(array_unique($userIds));

        if (in_array($actor->getAuthIdentifier(), $userIds, true)) {
            throw new AuthException('self_bulk_operation_forbidden', 'Bulk operations cannot target your own account.', 422);
        }

        $connection = $this->users->query(true)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $operation, $userIds): BulkUserResult {
            $users = $this->users->query(true)->whereKey($userIds)->lockForUpdate()->get();

            /** @var User $user */
            foreach ($users as $user) {
                match ($operation) {
                    UserBulkOperation::Enable => $user->forceFill(['is_active' => true])->save(),
                    UserBulkOperation::Disable => $this->disable($user),
                    UserBulkOperation::Delete => $this->delete($user),
                    UserBulkOperation::Restore => $user->restore(),
                };
                PrincipalChanged::dispatch($user->id, $operation->value);
            }

            $affectedUserIds = array_values($users->map(static fn (User $user): string => $user->id)->all());
            $this->audits->record('users.bulk_'.$operation->value, actor: $actor, metadata: [
                'user_ids' => $affectedUserIds,
                'affected' => $users->count(),
            ]);

            return new BulkUserResult($operation, $affectedUserIds, $users->count());
        }, 3);
    }

    /** Disable one principal and revoke its tokens. */
    private function disable(User $user): bool
    {
        $user->tokens()->delete();

        return $user->forceFill(['is_active' => false])->save();
    }

    /** Soft-delete one principal and revoke its tokens. */
    private function delete(User $user): bool
    {
        $user->tokens()->delete();

        return (bool) $user->delete();
    }
}

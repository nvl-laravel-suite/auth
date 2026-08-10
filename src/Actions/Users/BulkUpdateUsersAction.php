<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Results\BulkUserResult;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\MutationAuthorizer;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Applies one bounded principal lifecycle operation atomically.
 */
final readonly class BulkUpdateUsersAction
{
    /** Create the bulk mutation use case. */
    public function __construct(
        private FeatureGate $features,
        private MutationAuthorizer $authorization,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
        private PrincipalSessionContainment $sessions,
    ) {}

    /**
     * Apply one operation to at most one hundred principals.
     *
     * @param  list<string>  $userIds
     */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        UserBulkOperation $operation,
        array $userIds,
    ): BulkUserResult {
        $this->features->assertAllowed(
            AuthFeature::PrincipalManagement,
            in_array($operation, [UserBulkOperation::Delete, UserBulkOperation::Restore], true)
                ? FeatureOperation::Revoke
                : FeatureOperation::Update,
        );
        $actor = $this->authorization->authorize($authority, match ($operation) {
            UserBulkOperation::Delete => 'nvl-auth.users.delete',
            UserBulkOperation::Restore => 'nvl-auth.users.restore',
            default => 'nvl-auth.users.update',
        });
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        if ($userIds === []
            || count($userIds) > 100
            || count(array_filter($userIds, static fn (string $id): bool => ! Str::isUuid($id))) > 0) {
            throw new AuthException('invalid_bulk_selection', 'Bulk operations require between one and one hundred users.', 422);
        }

        $userIds = array_values(array_unique($userIds));

        if ($authority instanceof Authenticatable
            && in_array($authority->getAuthIdentifier(), $userIds, true)) {
            throw new AuthException('self_bulk_operation_forbidden', 'Bulk operations cannot target your own account.', 422);
        }

        $connection = $this->users->query(true)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $context, $metadata, $operation, $userIds): BulkUserResult {
            $users = $this->users->query(true)->whereKey($userIds)->lockForUpdate()->get();

            /** @var User $user */
            foreach ($users as $user) {
                match ($operation) {
                    UserBulkOperation::Enable => $this->setActive($user, new UpdateUserStatusData(true)),
                    UserBulkOperation::Disable => $this->setActive($user, new UpdateUserStatusData(false), $context),
                    UserBulkOperation::Delete => $this->delete($user, $context),
                    UserBulkOperation::Restore => $this->restore($user, $context),
                };
                PrincipalChanged::dispatch($this->attributes->identifier($user), $operation->value, $metadata);
            }

            $affectedUserIds = array_values($users->map(
                fn (User $user): string => $this->attributes->identifier($user),
            )->all());
            $this->audits->record('users.bulk_'.$operation->value, actor: $actor, metadata: [
                'user_ids' => $affectedUserIds,
                'affected' => $users->count(),
                ...$metadata,
            ]);

            return new BulkUserResult($operation, $affectedUserIds, $users->count());
        }, 3);
    }

    /** Apply validated active state and contain credentials when disabling. */
    private function setActive(
        User $user,
        UpdateUserStatusData $data,
        ?SystemMutationContext $context = null,
    ): bool {
        if (! $data->active) {
            $this->sessions->contain($user, 'disabled', $context);
        }

        return $user->update($this->attributes->map($data->toArray()));
    }

    /** Soft-delete one principal and revoke its tokens. */
    private function delete(User $user, ?SystemMutationContext $context): bool
    {
        $this->sessions->contain($user, 'deleted', $context);

        return (bool) $user->delete();
    }

    /** Restore one principal after invalidating any pre-deletion credentials. */
    private function restore(User $user, ?SystemMutationContext $context): bool
    {
        $restored = (bool) $user->restore();
        $this->sessions->contain($user, 'restored', $context);

        return $restored;
    }
}

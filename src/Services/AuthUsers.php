<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use DateTimeZone;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Events\DomainEventDispatcher;

/** Complete native AuthUsers operations.
 * @api
 */
final readonly class AuthUsers
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private MutationAuthorizer $authorization, private UserLocator $users, private AuthAuditRecorder $audits, private PrincipalAttributeMapper $attributes, private PrincipalSessionContainment $sessions, private AuthMemberships $owners, private AuthOwnershipState $ownershipState, private DomainEventDispatcher $domainEvents, private ManagementAuthorizer $createAuthorization, private AuthModelRegistry $models, private Container $container, private AuthConfiguration $configuration, private AccountConfirmation $confirmation, private AuthOperationBoundary $operations, private ManagementAuthorizer $updateAuthorization) {}

    /**
     * Apply one operation to at most one hundred principals.
     *
     * @param  list<string>  $userIds
     * @return array<string, mixed>
     */
    public function bulkUpdate(Authenticatable|SystemMutationContext $authority, UserBulkOperation $operation, array $userIds): array
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, in_array($operation, [UserBulkOperation::Delete, UserBulkOperation::Restore], true) ? FeatureOperation::Revoke : FeatureOperation::Update);
        $ability = match ($operation) {
            UserBulkOperation::Delete => 'nvl.auth.users.delete',
            UserBulkOperation::Restore => 'nvl.auth.users.restore',
            default => 'nvl.auth.users.update',
        };
        if ($userIds === [] || count($userIds) > 100 || count(array_filter($userIds, static fn (string $id): bool => ! Str::isUuid($id))) > 0) {
            throw new AuthException('invalid_bulk_selection', 'Bulk operations require between one and one hundred users.', 422);
        }
        $userIds = array_values(array_unique($userIds));
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $actor = $context === null ? $authority : $this->authorization->authorize($context, $ability);
        if ($authority instanceof Authenticatable && in_array($authority->getAuthIdentifier(), $userIds, true)) {
            throw new AuthException('self_bulk_operation_forbidden', 'Bulk operations cannot target your own account.', 422);
        }
        $connection = $this->users->query(true)->getModel()->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($ability, $actor, $authority, $context, $metadata, $operation, $userIds): array {
            $users = $this->users->query(true)->whereKey($userIds)->lockForUpdate()->get();
            /** @var User $user */
            foreach ($users as $user) {
                if ($authority instanceof Authenticatable) {
                    $this->authorization->authorize($authority, $ability, $user);
                }
                match ($operation) {
                    UserBulkOperation::Enable => $this->bulkUpdateSetActive($user, ['active' => true]),
                    UserBulkOperation::Disable => $this->bulkUpdateSetActive($user, ['active' => false], $context),
                    UserBulkOperation::Delete => $this->bulkUpdateDelete($user, $context),
                    UserBulkOperation::Restore => $this->bulkUpdateRestore($user, $context),
                };
                $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), $operation->value, $metadata, AuthEventContext::centralIdentity()), $user->getConnection());
            }
            $affectedUserIds = array_values($users->map(fn (User $user): string => $this->attributes->identifier($user))->all());
            $this->audits->record('users.bulk_'.$operation->value, actor: $actor, metadata: ['user_ids' => $affectedUserIds, 'affected' => $users->count(), ...$metadata]);

            return ['operation' => $operation, 'userIds' => $affectedUserIds, 'affected' => $users->count()];
        }, 3);
    }

    /** Apply validated active state and contain credentials when disabling.
     * @param  array<string, mixed>  $data
     */
    private function bulkUpdateSetActive(User $user, array $data, ?SystemMutationContext $context = null): bool
    {
        $data = $this->validateUpdateUserStatus($data);
        if (! $data['active']) {
            if ($this->ownershipState->native()) {
                $this->owners->assertPrincipalCanBeDisabled(SubjectReference::fromAuthenticatable($user));
            }
            $this->sessions->contain($user, 'disabled', $context);
        }

        return $user->update($this->attributes->map($data));
    }

    /** Soft-delete one principal and revoke its tokens. */
    private function bulkUpdateDelete(User $user, ?SystemMutationContext $context): bool
    {
        if ($this->ownershipState->native()) {
            $this->owners->assertPrincipalCanBeDisabled(SubjectReference::fromAuthenticatable($user));
        }
        $this->sessions->contain($user, 'deleted', $context);

        return (bool) $user->delete();
    }

    /** Restore one principal after invalidating any pre-deletion credentials. */
    private function bulkUpdateRestore(User $user, ?SystemMutationContext $context): bool
    {
        $restored = (bool) $user->restore();
        $this->sessions->contain($user, 'restored', $context);

        return $restored;
    }

    /** Persist a principal and optional RBAC assignment atomically.
     * @param  array<string, mixed>  $data
     */
    public function create(Authenticatable $actor, array $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Issue);
        $data = $this->validateStoreUser($data);
        $this->createAuthorization->authorize($actor, 'nvl.auth.users.create');
        if ($data['roles'] !== [] || $data['permissions'] !== []) {
            $this->features->assertAllowed(AuthFeature::Rbac, FeatureOperation::Update);
            $this->createAuthorization->authorize($actor, 'nvl.auth.users.manageAccess');
        }
        $class = $this->models->userClass();
        $connection = (new $class)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($actor, $class, $data): User {
            $user = $class::query()->create($this->attributes->map(array_diff_key($data, array_flip(['roles', 'permissions']))));
            if ($data['roles'] !== [] || $data['permissions'] !== []) {
                $this->container->make(RbacManager::class)->assign($user, $data['roles'], $data['permissions']);
            }
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('user.created', subject: $reference, actor: $actor);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'created', ['email' => $this->attributes->value($user, PrincipalAttribute::Email)], AuthEventContext::centralIdentity()), $user->getConnection());

            return $user->refresh()->load(config('nvl-auth.features.rbac.enabled') === true ? ['roles', 'permissions'] : []);
        }, 3);
    }

    /** Delete the authenticated package principal and revoke every active credential.
     * @param  array<string, mixed>  $data
     */
    public function deleteOwnAccount(Authenticatable $subject, array $data, StatefulGuard $guard, Session $session): bool
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $data = $this->validateDeleteOwnAccount($data);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Revoke);
        $this->operations->central(AuthIdentityOperation::Profile, $subject);
        $user = $this->users->authenticated($subject);
        $this->confirmation->assertConfirmed($user, $data['currentPassword']);
        $deleted = DB::connection($user->getConnectionName())->transaction(function () use ($user): bool {
            $reference = SubjectReference::fromAuthenticatable($user);
            if ($this->ownershipState->native()) {
                $this->owners->assertPrincipalCanBeDisabled($reference);
            }
            $this->sessions->contain($user, 'self_deleted');
            $deleted = (bool) $user->delete();
            $this->audits->record('user.self_deleted', subject: $reference, actor: $user);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'self_deleted', context: AuthEventContext::centralIdentity()), $user->getConnection());

            return $deleted;
        }, 3);
        $guard->logout();
        $session->invalidate();
        $session->regenerateToken();
        if ($subject instanceof User) {
            $subject->setRawAttributes($user->getAttributes(), true);
        }

        return $deleted;
    }

    /** Soft delete one principal. */
    public function delete(Authenticatable|SystemMutationContext $authority, User|string $user): bool
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $actor = $this->authorization->authorize($authority, 'nvl.auth.users.delete', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user);
        if ($authority instanceof Authenticatable && $authority->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_delete_forbidden', 'You cannot delete your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $metadata, $user): bool {
            $reference = SubjectReference::fromAuthenticatable($user);
            if ($this->ownershipState->native()) {
                $this->owners->assertPrincipalCanBeDisabled($reference);
            }
            $this->sessions->contain($user, 'deleted', $context);
            $deleted = (bool) $user->delete();
            $this->audits->record('user.deleted', subject: $reference, actor: $actor, metadata: $metadata);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'deleted', $metadata, AuthEventContext::centralIdentity()), $user->getConnection());

            return $deleted;
        }, 3);
    }

    /** Restore one principal without silently re-enabling it. */
    public function restore(Authenticatable|SystemMutationContext $authority, User|string $user): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Revoke);
        $actor = $this->authorization->authorize($authority, 'nvl.auth.users.restore', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user, true);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $metadata, $user): User {
            $user->restore();
            $this->sessions->contain($user, 'restored', $context);
            $this->audits->record('user.restored', subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: $metadata);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'restored', $metadata, AuthEventContext::centralIdentity()), $user->getConnection());

            return $user->refresh();
        }, 3);
    }

    /** Persist the principal activation state.
     * @param  array<string, mixed>  $data
     */
    public function setActive(Authenticatable|SystemMutationContext $authority, User|string $user, array $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $data = $this->validateUpdateUserStatus($data);
        $actor = $this->authorization->authorize($authority, 'nvl.auth.users.update', $user);
        $metadata = $this->authorization->metadata($authority);
        $context = $authority instanceof SystemMutationContext ? $authority : null;
        $user = $this->users->find($user);
        if (! $data['active'] && $authority instanceof Authenticatable && $authority->getAuthIdentifier() === $user->getKey()) {
            throw new AuthException('self_disable_forbidden', 'You cannot disable your own account.', 422);
        }

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $context, $data, $metadata, $user): User {
            if (! $data['active']) {
                $this->owners->assertPrincipalCanBeDisabled(SubjectReference::fromAuthenticatable($user));
            }
            $user->update($this->attributes->map($data));
            if (! $data['active']) {
                $this->sessions->contain($user, 'disabled', $context);
            }
            $operation = $data['active'] ? 'enabled' : 'disabled';
            $this->audits->record("user.{$operation}", subject: SubjectReference::fromAuthenticatable($user), actor: $actor, metadata: $metadata);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), $operation, $metadata, AuthEventContext::centralIdentity()), $user->getConnection());

            return $user->refresh();
        }, 3);
    }

    /** Persist self-service profile changes.
     * @param  array<string, mixed>  $data
     */
    public function updateProfile(Authenticatable $subject, array $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $data = $this->validateUpdateProfile($data);
        $this->operations->central(AuthIdentityOperation::Profile, $subject);
        $user = $this->users->authenticated($subject);

        return DB::connection($user->getConnectionName())->transaction(function () use ($data, $user): User {
            $attributes = array_diff_key($data, array_flip(['currentPassword']));
            $submittedEmail = $attributes['email'] ?? null;
            $currentEmail = $this->attributes->value($user, PrincipalAttribute::Email);
            $emailChanged = is_string($submittedEmail) && is_string($currentEmail) && mb_strtolower(trim($submittedEmail)) !== mb_strtolower(trim($currentEmail));
            if ($emailChanged) {
                if (! array_key_exists('currentPassword', $data)) {
                    throw new AuthException('account_confirmation_required', 'Email changes require account confirmation.', 422);
                }
                $this->confirmation->assertConfirmed($user, $data['currentPassword']);
                $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);
                $normalizedEmail = mb_strtolower(trim($submittedEmail));
                if ($user::query()->where($this->attributes->column(PrincipalAttribute::Email), $normalizedEmail)->whereKeyNot($user->getKey())->exists()) {
                    throw new AuthException('email_unavailable', 'The email address is unavailable.', 422);
                }
                $attributes['emailVerified'] = false;
            }
            $user->update($this->attributes->map($attributes));
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('profile.updated', subject: $reference, actor: $user, metadata: ['attributes' => array_keys($attributes)]);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'profile_updated', ['attributes' => array_keys($attributes)], AuthEventContext::centralIdentity()), $user->getConnection());
            if ($emailChanged) {
                $this->updateProfileRequestEmailVerification($user, $data);
            }

            return $user->refresh();
        }, 3);
    }

    /** Emit the post-commit verification delivery for one changed email address.
     * @param  array<string, mixed>  $data
     */
    private function updateProfileRequestEmailVerification(User $user, array $data): void
    {
        $data = $this->validateUpdateProfile($data);
        $expiresAt = CarbonImmutable::now()->addMinutes($this->configuration->integerBetween('features.email_verification.settings.ttl_minutes', 60, 1, 10080));
        $reference = SubjectReference::fromAuthenticatable($user);
        $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::EmailVerification, type: AuthMessageType::EmailVerification, recipient: $user->getEmailForVerification(), payload: ['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'email_hash' => sha1($user->getEmailForVerification())], expiresAt: $expiresAt, locale: ! array_key_exists('locale', $data) ? null : $data['locale']), $this->deliveryContext->capture(true)), $user->getConnection());
        $this->audits->record('email_verification.requested', subject: $reference, actor: $user);
    }

    /** Persist a partial principal mutation.
     * @param  array<string, mixed>  $data
     */
    public function update(Authenticatable $actor, User|string $user, array $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $data = $this->validateUpdateUser($data);
        $user = $this->users->find($user, true);
        $this->updateAuthorization->authorize($actor, 'nvl.auth.users.update', $user);

        return DB::connection($user->getConnectionName())->transaction(function () use ($actor, $data, $user): User {
            $attributes = $data;
            $user->update($this->attributes->map($attributes));
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('user.updated', subject: $reference, actor: $actor, metadata: ['attributes' => array_keys($attributes)]);
            $this->domainEvents->dispatch(new PrincipalChanged($this->attributes->identifier($user), 'updated', ['attributes' => array_keys($attributes)], AuthEventContext::centralIdentity()), $user->getConnection());

            return $user->refresh()->load(config('nvl-auth.features.rbac.enabled') === true ? ['roles', 'permissions'] : []);
        }, 3);
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{currentPassword: string}
     */
    private function validateDeleteOwnAccount(array $data): array
    {
        if (array_diff(array_keys($data), ['currentPassword']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['currentPassword'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [currentPassword].');
        }
        Validator::make($data, ['currentPassword' => ['required', 'string', 'max:4096']])->validate();

        return $data;
    }

    /** Native Auth operation.
     * @param  array<array-key, mixed>  $payload
     */
    private function validateStoreUserAssertJsonPayloadIsBounded(array $payload, string $field): void
    {
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException("User {$field} must be JSON serializable.", previous: $exception);
        }
        if (strlen($encoded) > 65535) {
            throw new InvalidArgumentException("User {$field} must not exceed 65,535 encoded bytes.");
        }
    }

    /** Native Auth operation.
     * @param  array<array-key, mixed>  $values
     *
     * @phpstan-assert list<string> $values
     */
    private function validateStoreUserAssertStringListIsBounded(array $values, int $maximum, string $field): void
    {
        if (! array_is_list($values) || count($values) > $maximum) {
            throw new InvalidArgumentException("User {$field} must be a list containing at most {$maximum} values.");
        }
        $seen = [];
        foreach ($values as $value) {
            if (! is_string($value) || trim($value) === '' || mb_strlen($value) > 160) {
                throw new InvalidArgumentException("User {$field} values must contain between one and 160 characters.");
            }
            if (isset($seen[$value])) {
                throw new InvalidArgumentException("User {$field} values must be distinct.");
            }
            $seen[$value] = true;
        }
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name: string, email: string, password: string|null, active: bool, locale: string, timezone: string, profile: array<array-key, mixed>, preferences: array<array-key, mixed>, roles: list<string>, permissions: list<string>, emailVerified: bool}
     */
    private function validateStoreUser(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'email', 'password', 'active', 'locale', 'timezone', 'profile', 'preferences', 'roles', 'permissions', 'emailVerified']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_string($data['name'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [name].');
        }
        if (! is_string($data['email'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [email].');
        }
        if (! (array_key_exists('password', $data) && $data['password'] === null || is_string($data['password'] ?? null))) {
            throw new InvalidArgumentException('Invalid Auth input [password].');
        }
        if (! array_key_exists('active', $data)) {
            $data['active'] = true;
        }
        if (! is_bool($data['active'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [active].');
        }
        if (! array_key_exists('locale', $data)) {
            $data['locale'] = 'en';
        }
        if (! is_string($data['locale'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [locale].');
        }
        if (! array_key_exists('timezone', $data)) {
            $data['timezone'] = 'UTC';
        }
        if (! is_string($data['timezone'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [timezone].');
        }
        if (! array_key_exists('profile', $data)) {
            $data['profile'] = [];
        }
        if (! is_array($data['profile'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [profile].');
        }
        if (! array_key_exists('preferences', $data)) {
            $data['preferences'] = [];
        }
        if (! is_array($data['preferences'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [preferences].');
        }
        if (! array_key_exists('roles', $data)) {
            $data['roles'] = [];
        }
        if (! is_array($data['roles'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [roles].');
        }
        if (! array_key_exists('permissions', $data)) {
            $data['permissions'] = [];
        }
        if (! is_array($data['permissions'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [permissions].');
        }
        if (! array_key_exists('emailVerified', $data)) {
            $data['emailVerified'] = false;
        }
        if (! is_bool($data['emailVerified'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [emailVerified].');
        }
        if (trim($data['name']) === '' || mb_strlen($data['name']) > 160) {
            throw new InvalidArgumentException('User names must contain between one and 160 characters.');
        }
        if (filter_var($data['email'], FILTER_VALIDATE_EMAIL) === false || mb_strlen($data['email']) > 254) {
            throw new InvalidArgumentException('A valid user email address is required.');
        }
        if ($data['password'] !== null && mb_strlen($data['password']) < 12) {
            throw new InvalidArgumentException('User passwords must contain at least 12 characters.');
        }
        if (! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $data['locale'])) {
            throw new InvalidArgumentException('A valid user locale is required.');
        }
        if (! in_array($data['timezone'], DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid user timezone is required.');
        }
        $this->validateStoreUserAssertJsonPayloadIsBounded($data['profile'], 'profile');
        $this->validateStoreUserAssertJsonPayloadIsBounded($data['preferences'], 'preferences');
        $this->validateStoreUserAssertStringListIsBounded($data['roles'], 100, 'roles');
        $this->validateStoreUserAssertStringListIsBounded($data['permissions'], 250, 'permissions');

        return $data;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name?: string, email?: string, locale?: string, timezone?: string, profile?: array<array-key, mixed>, preferences?: array<array-key, mixed>, currentPassword?: string}
     */
    private function validateUpdateProfile(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'email', 'locale', 'timezone', 'profile', 'preferences', 'currentPassword']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        $validated = [];
        if (array_key_exists('name', $data)) {
            if (! is_string($data['name'])) {
                throw new InvalidArgumentException('Invalid Auth input [name].');
            }
            $validated['name'] = $data['name'];
        }
        if (array_key_exists('email', $data)) {
            if (! is_string($data['email'])) {
                throw new InvalidArgumentException('Invalid Auth input [email].');
            }
            $validated['email'] = $data['email'];
        }
        if (array_key_exists('locale', $data)) {
            if (! is_string($data['locale'])) {
                throw new InvalidArgumentException('Invalid Auth input [locale].');
            }
            $validated['locale'] = $data['locale'];
        }
        if (array_key_exists('timezone', $data)) {
            if (! is_string($data['timezone'])) {
                throw new InvalidArgumentException('Invalid Auth input [timezone].');
            }
            $validated['timezone'] = $data['timezone'];
        }
        if (array_key_exists('profile', $data)) {
            if (! is_array($data['profile'])) {
                throw new InvalidArgumentException('Invalid Auth input [profile].');
            }
            $validated['profile'] = $data['profile'];
        }
        if (array_key_exists('preferences', $data)) {
            if (! is_array($data['preferences'])) {
                throw new InvalidArgumentException('Invalid Auth input [preferences].');
            }
            $validated['preferences'] = $data['preferences'];
        }
        if (array_key_exists('currentPassword', $data)) {
            if (! is_string($data['currentPassword'])) {
                throw new InvalidArgumentException('Invalid Auth input [currentPassword].');
            }
            $validated['currentPassword'] = $data['currentPassword'];
        }
        if (isset($validated['email'])) {
            $validated['email'] = mb_strtolower(trim($validated['email']));
        }
        Validator::make($validated, ['name' => ['sometimes', 'string', 'max:160'], 'email' => ['sometimes', 'email:rfc', 'max:320'], 'locale' => ['sometimes', 'string', 'regex:/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/'], 'timezone' => ['sometimes', 'timezone:all'], 'profile' => ['sometimes', 'array'], 'preferences' => ['sometimes', 'array'], 'currentPassword' => ['sometimes', 'string', 'max:4096']])->validate();

        return $validated;
    }

    /** Native Auth operation.
     * @param  array<array-key, mixed>  $payload
     */
    private function validateUpdateUserAssertJsonPayloadIsBounded(array $payload, string $field): void
    {
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException("User {$field} must be JSON serializable.", previous: $exception);
        }
        if (strlen($encoded) > 65535) {
            throw new InvalidArgumentException("User {$field} must not exceed 65,535 encoded bytes.");
        }
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{name?: string, email?: string, password?: string|null, locale?: string, timezone?: string, profile?: array<array-key, mixed>, preferences?: array<array-key, mixed>, emailVerified?: bool}
     */
    private function validateUpdateUser(array $data): array
    {
        if (array_diff(array_keys($data), ['name', 'email', 'password', 'locale', 'timezone', 'profile', 'preferences', 'emailVerified']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        $validated = [];
        if (array_key_exists('name', $data)) {
            if (! is_string($data['name'])) {
                throw new InvalidArgumentException('Invalid Auth input [name].');
            }
            $validated['name'] = $data['name'];
        }
        if (array_key_exists('email', $data)) {
            if (! is_string($data['email'])) {
                throw new InvalidArgumentException('Invalid Auth input [email].');
            }
            $validated['email'] = $data['email'];
        }
        if (array_key_exists('password', $data)) {
            if (! ($data['password'] === null || is_string($data['password']))) {
                throw new InvalidArgumentException('Invalid Auth input [password].');
            }
            $validated['password'] = $data['password'];
        }
        if (array_key_exists('locale', $data)) {
            if (! is_string($data['locale'])) {
                throw new InvalidArgumentException('Invalid Auth input [locale].');
            }
            $validated['locale'] = $data['locale'];
        }
        if (array_key_exists('timezone', $data)) {
            if (! is_string($data['timezone'])) {
                throw new InvalidArgumentException('Invalid Auth input [timezone].');
            }
            $validated['timezone'] = $data['timezone'];
        }
        if (array_key_exists('profile', $data)) {
            if (! is_array($data['profile'])) {
                throw new InvalidArgumentException('Invalid Auth input [profile].');
            }
            $validated['profile'] = $data['profile'];
        }
        if (array_key_exists('preferences', $data)) {
            if (! is_array($data['preferences'])) {
                throw new InvalidArgumentException('Invalid Auth input [preferences].');
            }
            $validated['preferences'] = $data['preferences'];
        }
        if (array_key_exists('emailVerified', $data)) {
            if (! is_bool($data['emailVerified'])) {
                throw new InvalidArgumentException('Invalid Auth input [emailVerified].');
            }
            $validated['emailVerified'] = $data['emailVerified'];
        }
        if (isset($validated['name']) && (trim($validated['name']) === '' || mb_strlen($validated['name']) > 160)) {
            throw new InvalidArgumentException('User names must contain between one and 160 characters.');
        }
        if (isset($validated['email']) && (filter_var($validated['email'], FILTER_VALIDATE_EMAIL) === false || mb_strlen($validated['email']) > 254)) {
            throw new InvalidArgumentException('A valid user email address is required.');
        }
        if (isset($validated['password']) && mb_strlen($validated['password']) < 12) {
            throw new InvalidArgumentException('User passwords must contain at least 12 characters.');
        }
        if (isset($validated['locale']) && ! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $validated['locale'])) {
            throw new InvalidArgumentException('A valid user locale is required.');
        }
        if (isset($validated['timezone']) && ! in_array($validated['timezone'], DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid user timezone is required.');
        }
        if (isset($validated['profile'])) {
            $this->validateUpdateUserAssertJsonPayloadIsBounded($validated['profile'], 'profile');
        }
        if (isset($validated['preferences'])) {
            $this->validateUpdateUserAssertJsonPayloadIsBounded($validated['preferences'], 'preferences');
        }

        return $validated;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return array{active: bool}
     */
    private function validateUpdateUserStatus(array $data): array
    {
        if (array_diff(array_keys($data), ['active']) !== []) {
            throw new InvalidArgumentException('Unknown or protected Auth input fields.');
        }
        if (! is_bool($data['active'] ?? null)) {
            throw new InvalidArgumentException('Invalid Auth input [active].');
        }
        Validator::make($data, ['active' => ['required', 'boolean']])->validate();

        return $data;
    }
}

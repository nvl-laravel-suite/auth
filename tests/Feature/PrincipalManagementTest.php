<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Users\BulkUpdateUsersAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\DeleteOwnAccountAction;
use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\RestoreUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\SuggestUsersAction;
use Nvl\Auth\Actions\Users\SyncUserPermissionsAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Data\Mutations\DeleteOwnAccountData;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Data\Mutations\StoreUserData;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;

it('owns a complete principal lifecycle and fails disabled login closed', function (): void {
    $actor = $this->user('owner@example.test');
    $permission = app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('users.create', 'Create Principals'));
    $role = app(CreateRoleAction::class)->execute($actor, new StoreRoleData('manage', 'Super Administrator', permissions: ['users.create']));
    Event::fake([PrincipalChanged::class]);

    $user = app(CreateUserAction::class)->execute($actor, new StoreUserData(
        name: 'Package User',
        email: 'package.user@example.test',
        password: 'SecurePassword123',
        roles: ['manage'],
        permissions: ['users.create'],
        emailVerified: true,
    ));

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->getTable())->toBe('nvl_auth_users')
        ->and(Hash::check('SecurePassword123', (string) $user->password))->toBeTrue()
        ->and($user->hasRole('manage'))->toBeTrue()
        ->and($user->hasDirectPermission('users.create'))->toBeTrue();

    $user->createToken('nvl-auth:mobile', ['users.create']);
    $disabled = app(SetUserActiveAction::class)->execute($actor, $user, false);

    expect($disabled->is_active)->toBeFalse()
        ->and($disabled->tokens()->count())->toBe(0)
        ->and(fn () => app(LoginAction::class)->execute(new LoginData($user->email, 'SecurePassword123')))
        ->toThrow(AuthException::class, 'credentials');

    app(SetUserActiveAction::class)->execute($actor, $user, true);
    app(SyncUserRolesAction::class)->execute($actor, $user, []);
    app(SyncUserPermissionsAction::class)->execute($actor, $user, ['users.create']);
    app(DeleteUserAction::class)->execute($actor, $user);

    expect($user->fresh()->trashed())->toBeTrue();

    $restored = app(RestoreUserAction::class)->execute($actor, $user->id);

    expect($restored->trashed())->toBeFalse()
        ->and($restored->is_active)->toBeTrue()
        ->and($restored->hasDirectPermission('users.create'))->toBeTrue();

    Event::assertDispatched(PrincipalChanged::class);
});

it('supports profile, suggestions, and bounded bulk lifecycle operations', function (): void {
    $actor = $this->user('profile.owner@example.test');
    $first = app(CreateUserAction::class)->execute($actor, new StoreUserData(
        name: 'Suggested Alpha',
        email: 'alpha@example.test',
        password: 'SecurePassword123',
    ));
    $second = app(CreateUserAction::class)->execute($actor, new StoreUserData(
        name: 'Suggested Beta',
        email: 'beta@example.test',
        password: 'SecurePassword123',
    ));

    $profile = app(UpdateProfileAction::class)->execute($actor, new UpdateProfileData(
        name: 'Updated Owner',
        locale: 'bg',
        timezone: 'Europe/Sofia',
        profile: ['phone' => '+359000000000'],
        preferences: ['theme' => 'dark'],
    ));
    $suggestions = app(SuggestUsersAction::class)->execute($actor, 'Suggested');
    $result = app(BulkUpdateUsersAction::class)->execute(
        $actor,
        UserBulkOperation::Disable,
        [$first->id, $second->id],
    );

    expect($profile->name)->toBe('Updated Owner')
        ->and($profile->profile)->toBe(['phone' => '+359000000000'])
        ->and($profile->preferences)->toBe(['theme' => 'dark'])
        ->and($suggestions)->toHaveCount(2)
        ->and($result->affected)->toBe(2)
        ->and($first->fresh()->is_active)->toBeFalse()
        ->and($second->fresh()->is_active)->toBeFalse();
});

it('rejects invalid direct principal and RBAC input before persistence', function (): void {
    expect(fn (): StoreUserData => new StoreUserData(
        name: 'Invalid Timezone',
        email: 'invalid.timezone@example.test',
        password: 'SecurePassword123',
        timezone: 'Not/A-Timezone',
    ))->toThrow(InvalidArgumentException::class, 'timezone')
        ->and(fn (): StoreRoleData => new StoreRoleData(
            name: 'duplicated-permissions',
            permissions: ['users.create', 'users.create'],
        ))->toThrow(InvalidArgumentException::class, 'distinct');

    expect(User::query()->where('email', 'invalid.timezone@example.test')->exists())->toBeFalse();
});

it('changes self-service email sparsely after confirmation and restarts verification', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    Event::fake([AuthDeliveryRequested::class, PrincipalChanged::class]);
    $user = $this->user('old@example.test');
    $user->forceFill(['email_verified_at' => now(), 'locale' => 'bg'])->save();

    $updated = app(UpdateProfileAction::class)->execute($user, new UpdateProfileData(
        email: ' New.Address@Example.Test ',
        currentPassword: 'correct-password',
    ));

    expect($updated->email)->toBe('new.address@example.test')
        ->and($updated->email_verified_at)->toBeNull()
        ->and($updated->name)->toBe('Test User')
        ->and($updated->locale)->toBe('bg');
    Event::assertDispatched(AuthDeliveryRequested::class, static fn (AuthDeliveryRequested $event): bool => $event->request->recipient === 'new.address@example.test');
});

it('rejects a self-service email conflict without changing profile state', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    $user = $this->user('unchanged@example.test');
    $this->user('taken@example.test');

    expect(fn () => app(UpdateProfileAction::class)->execute($user, new UpdateProfileData(
        email: 'taken@example.test',
        currentPassword: 'correct-password',
    )))->toThrow(AuthException::class, 'unavailable')
        ->and($user->refresh()->email)->toBe('unchanged@example.test');
});

it('confirms, revokes credentials, and invalidates the session for self deletion', function (): void {
    $user = $this->user('self.delete@example.test');
    $user->createToken('nvl-auth:test', ['profile:read']);
    Auth::guard('web')->login($user);
    $request = app('request');
    $request->setLaravelSession(app('session')->driver());

    expect(app(DeleteOwnAccountAction::class)->execute(
        $user,
        new DeleteOwnAccountData('correct-password'),
    ))->toBeTrue()
        ->and(Auth::guard('web')->check())->toBeFalse()
        ->and($user->trashed())->toBeTrue()
        ->and($user->tokens()->count())->toBe(0);
});

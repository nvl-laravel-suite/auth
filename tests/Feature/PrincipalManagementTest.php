<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Users\BulkUpdateUsersAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\RestoreUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\SuggestUsersAction;
use Nvl\Auth\Actions\Users\SyncUserPermissionsAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\CreateUserData;
use Nvl\Auth\ValueObjects\PermissionData;
use Nvl\Auth\ValueObjects\ProfileData;
use Nvl\Auth\ValueObjects\RoleData;

it('owns a complete principal lifecycle and fails disabled login closed', function (): void {
    $actor = $this->user('owner@example.test');
    app(CreatePermissionAction::class)->execute($actor, new PermissionData('documents.read'));
    app(CreatePermissionAction::class)->execute($actor, new PermissionData('documents.write'));
    app(CreateRoleAction::class)->execute($actor, new RoleData('editor', permissions: ['documents.read']));
    Event::fake([PrincipalChanged::class]);

    $user = app(CreateUserAction::class)->execute($actor, new CreateUserData(
        name: 'Package User',
        email: 'package.user@example.test',
        password: 'SecurePassword123',
        roles: ['editor'],
        permissions: ['documents.write'],
        emailVerified: true,
    ));

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->getTable())->toBe('nvl_auth_users')
        ->and(Hash::check('SecurePassword123', (string) $user->password))->toBeTrue()
        ->and($user->hasRole('editor'))->toBeTrue()
        ->and($user->hasDirectPermission('documents.write'))->toBeTrue();

    $user->createToken('nvl-auth:mobile', ['documents.read']);
    $disabled = app(SetUserActiveAction::class)->execute($actor, $user, false);

    expect($disabled->is_active)->toBeFalse()
        ->and($disabled->tokens()->count())->toBe(0)
        ->and(fn () => app(LoginAction::class)->execute($user->email, 'SecurePassword123'))
        ->toThrow(AuthException::class, 'credentials');

    app(SetUserActiveAction::class)->execute($actor, $user, true);
    app(SyncUserRolesAction::class)->execute($actor, $user, []);
    app(SyncUserPermissionsAction::class)->execute($actor, $user, ['documents.read']);
    app(DeleteUserAction::class)->execute($actor, $user);

    expect($user->fresh()->trashed())->toBeTrue();

    $restored = app(RestoreUserAction::class)->execute($actor, $user->id);

    expect($restored->trashed())->toBeFalse()
        ->and($restored->is_active)->toBeTrue()
        ->and($restored->hasDirectPermission('documents.read'))->toBeTrue();

    Event::assertDispatched(PrincipalChanged::class);
});

it('supports profile, suggestions, and bounded bulk lifecycle operations', function (): void {
    $actor = $this->user('profile.owner@example.test');
    $first = app(CreateUserAction::class)->execute($actor, new CreateUserData(
        name: 'Suggested Alpha',
        email: 'alpha@example.test',
        password: 'SecurePassword123',
    ));
    $second = app(CreateUserAction::class)->execute($actor, new CreateUserData(
        name: 'Suggested Beta',
        email: 'beta@example.test',
        password: 'SecurePassword123',
    ));

    $profile = app(UpdateProfileAction::class)->execute($actor, new ProfileData(
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
    expect(fn (): CreateUserData => new CreateUserData(
        name: 'Invalid Timezone',
        email: 'invalid.timezone@example.test',
        password: 'SecurePassword123',
        timezone: 'Not/A-Timezone',
    ))->toThrow(InvalidArgumentException::class, 'timezone')
        ->and(fn (): RoleData => new RoleData(
            name: 'duplicated-permissions',
            permissions: ['documents.read', 'documents.read'],
        ))->toThrow(InvalidArgumentException::class, 'distinct');

    expect(User::query()->where('email', 'invalid.timezone@example.test')->exists())->toBeFalse();
});

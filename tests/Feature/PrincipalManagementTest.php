<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Users\BulkUpdateUsersAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\DeleteOwnAccountAction;
use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\ListUsersAction;
use Nvl\Auth\Actions\Users\RestoreUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\ShowUserAction;
use Nvl\Auth\Actions\Users\SuggestUsersAction;
use Nvl\Auth\Actions\Users\SyncUserPermissionsAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Data\Mutations\DeleteOwnAccountData;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Data\Mutations\StoreUserData;
use Nvl\Auth\Data\Mutations\SyncUserPermissionsData;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Events\RbacAssignmentChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\SystemMutationContext;

it('owns a complete principal lifecycle and fails disabled login closed', function (): void {
    $actor = $this->user('owner@example.test');
    $permission = app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('users.create', 'Create Principals'));
    $role = app(CreateRoleAction::class)->execute($actor, new StoreRoleData('manage', 'Super Administrator', permissions: ['users.create']));
    Event::fake([PrincipalChanged::class, RbacAssignmentChanged::class]);

    $user = app(CreateUserAction::class)->execute($actor, new StoreUserData(
        name: 'Package User',
        email: 'package.user@example.test',
        password: 'SecurePassword123',
        roles: ['manage'],
        permissions: ['users.create'],
        emailVerified: true,
    ));

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->getTable())->toBe(AuthTables::Users)
        ->and(Hash::check('SecurePassword123', (string) $user->password))->toBeTrue()
        ->and($user->hasRole('manage'))->toBeTrue()
        ->and($user->hasDirectPermission('users.create'))->toBeTrue();

    $user->createToken('nvl-auth:mobile', ['users.create']);
    $disabled = app(SetUserActiveAction::class)->execute($actor, $user, new UpdateUserStatusData(false));

    expect($disabled->is_active)->toBeFalse()
        ->and($disabled->tokens()->count())->toBe(0)
        ->and(fn () => app(LoginAction::class)->execute(new LoginData($user->email, 'SecurePassword123')))
        ->toThrow(AuthException::class, 'credentials');

    app(SetUserActiveAction::class)->execute($actor, $user, new UpdateUserStatusData(true));
    app(SyncUserRolesAction::class)->execute($actor, $user, new SyncUserRolesData([]));
    app(SyncUserPermissionsAction::class)->execute($actor, $user, new SyncUserPermissionsData(['users.create']));
    app(DeleteUserAction::class)->execute($actor, $user);

    expect($user->fresh()->trashed())->toBeTrue();

    $restored = app(RestoreUserAction::class)->execute($actor, $user->id);

    expect($restored->trashed())->toBeFalse()
        ->and($restored->is_active)->toBeTrue()
        ->and($restored->hasDirectPermission('users.create'))->toBeTrue();

    Event::assertDispatched(PrincipalChanged::class);
    Event::assertDispatched(RbacAssignmentChanged::class, 3);
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
    $first->forceFill(['remember_token' => 'first-remember'])->save();
    $second->forceFill(['remember_token' => 'second-remember'])->save();
    $first->createToken('nvl-auth:first', ['profile:read']);
    $second->createToken('nvl-auth:second', ['profile:read']);

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
        ->and($second->fresh()->is_active)->toBeFalse()
        ->and($first->fresh()->remember_token)->not->toBe('first-remember')
        ->and($second->fresh()->remember_token)->not->toBe('second-remember')
        ->and($first->tokens()->count())->toBe(0)
        ->and($second->tokens()->count())->toBe(0);
});

it('passes resolved principal targets to individual and bulk management policy decisions', function (): void {
    $actor = $this->user('policy-actor@example.test');
    $first = $this->user('policy-first@example.test');
    $second = $this->user('policy-second@example.test');
    $access = new class implements AuthManagementAccess
    {
        /** @var list<mixed> */
        public array $targets = [];

        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            $this->targets[] = $target;

            return $target instanceof User;
        }
    };
    app()->instance(AuthManagementAccess::class, $access);

    $shown = app(ShowUserAction::class)->execute($actor, $first->id);
    $result = app(BulkUpdateUsersAction::class)->execute(
        $actor,
        UserBulkOperation::Disable,
        [$first->id, $second->id],
    );

    expect($shown->is($first))->toBeTrue()
        ->and($result->affected)->toBe(2)
        ->and($access->targets)->toHaveCount(3)
        ->and($access->targets)->each->toBeInstanceOf(User::class);
});

it('keeps eager-loaded principal list queries independent of fixture size', function (): void {
    $actor = $this->user('query-actor@example.test');
    $measure = function () use ($actor): int {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $page = app(ListUsersAction::class)->execute($actor, perPage: 100);
        $queryCount = count(DB::getQueryLog());

        foreach ($page->items() as $user) {
            $user->roles->count();
            $user->permissions->count();
        }

        expect(DB::getQueryLog())->toHaveCount($queryCount);
        DB::disableQueryLog();

        return $queryCount;
    };

    $this->user('query-user-1@example.test');
    $singleQueryCount = $measure();

    foreach (range(2, 25) as $index) {
        $this->user("query-user-{$index}@example.test");
    }

    $populatedQueryCount = $measure();

    expect($singleQueryCount)->toBeLessThanOrEqual(4)
        ->and($populatedQueryCount)->toBe($singleQueryCount);
});

it('contains browser credentials during actorless domain deactivation', function (): void {
    config()->set('session.driver', 'database');
    config()->set('session.connection', 'testing');
    config()->set('session.table', 'sessions');
    Schema::connection('testing')->create('sessions', function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->uuid('user_id')->nullable()->index();
        $table->text('payload');
        $table->integer('last_activity');
    });
    $user = $this->user('domain-transition@example.test');
    $user->forceFill(['remember_token' => 'remember-me'])->save();
    $user->createToken('nvl-auth:browser', ['profile:read']);
    DB::connection('testing')->table('sessions')->insert([
        'id' => 'existing-browser-session',
        'user_id' => $user->id,
        'payload' => 'payload',
        'last_activity' => now()->timestamp,
    ]);

    try {
        $updated = app(SetUserActiveAction::class)->execute(
            new SystemMutationContext('Compliance failure', 'compliance-456', metadata: ['case' => '456']),
            $user,
            new UpdateUserStatusData(false),
        );

        $audit = AuthAudit::query()->where('action', 'user.disabled')->firstOrFail();

        expect($updated->is_active)->toBeFalse()
            ->and($updated->remember_token)->not->toBe('remember-me')
            ->and($updated->tokens()->count())->toBe(0)
            ->and(DB::connection('testing')->table('sessions')->where('user_id', $user->id)->exists())->toBeFalse()
            ->and($audit->actor_id)->toBeNull()
            ->and($audit->metadata['system']['correlation_id'])->toBe('compliance-456');

        $reenabled = app(SetUserActiveAction::class)->execute(
            new SystemMutationContext('Compliance restored', 'compliance-456-restored'),
            $user,
            new UpdateUserStatusData(true),
        );

        expect($reenabled->is_active)->toBeTrue();
    } finally {
        Schema::connection('testing')->dropIfExists('sessions');
    }
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
        ->and($updated->locale)->toBe('bg')
        ->and(AuthAudit::query()->where('action', 'profile.updated')->exists())->toBeTrue()
        ->and(AuthAudit::query()->where('action', 'email_verification.requested')->exists())->toBeTrue();
    Event::assertDispatched(AuthDeliveryRequested::class, static fn (AuthDeliveryRequested $event): bool => $event->request->recipient === 'new.address@example.test');
    Event::assertDispatched(PrincipalChanged::class, static fn (PrincipalChanged $event): bool => $event->operation === 'profile_updated'
        && in_array('emailVerified', $event->payload['attributes'] ?? [], true));
});

it('updates a nonsensitive profile field without account confirmation', function (): void {
    $user = $this->user('profile-name@example.test');

    $updated = app(UpdateProfileAction::class)->execute($user, new UpdateProfileData(
        name: 'Updated Without Confirmation',
    ));

    expect($updated->name)->toBe('Updated Without Confirmation')
        ->and($updated->email)->toBe('profile-name@example.test');
});

it('requires valid account confirmation before changing email', function (UpdateProfileData $data, string $code): void {
    $user = $this->user('confirmation-required@example.test');
    $failure = null;

    try {
        app(UpdateProfileAction::class)->execute($user, $data);
    } catch (AuthException $exception) {
        $failure = $exception;
    }

    expect($failure)->toBeInstanceOf(AuthException::class)
        ->errorCode->toBe($code)
        ->and($user->refresh()->email)->toBe('confirmation-required@example.test');
})->with([
    'missing current password' => [
        new UpdateProfileData(email: 'missing-confirmation@example.test'),
        'account_confirmation_required',
    ],
    'incorrect current password' => [
        new UpdateProfileData(
            email: 'invalid-confirmation@example.test',
            currentPassword: 'incorrect-password',
        ),
        'account_confirmation_invalid',
    ],
]);

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

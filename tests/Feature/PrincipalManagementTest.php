<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Events\RbacAssignmentChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\AuthUserReader;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\ValueObjects\SystemMutationContext;

it('rejects a malformed host token relationship before credential containment', function (): void {
    $principal = new class extends Illuminate\Foundation\Auth\User
    {
        public function tokens(): string
        {
            return 'invalid-token-relationship';
        }
    };

    expect(fn () => app(PrincipalSessionContainment::class)->contain($principal, 'deactivate'))
        ->toThrow(AuthException::class, 'token relationship');
});

it('owns a complete principal lifecycle and fails disabled login closed', function (): void {
    $actor = $this->user('owner@example.test');
    $permission = app(AuthPermissions::class)->create($actor, ['name' => 'users.create', 'displayName' => 'Create Principals']);
    $role = app(AuthRoles::class)->create($actor, ['name' => 'manage', 'displayName' => 'Super Administrator', 'permissions' => ['users.create']]);
    Event::fake([PrincipalChanged::class, RbacAssignmentChanged::class]);

    $user = app(AuthUsers::class)->create($actor, ['name' => 'Package User', 'email' => 'package.user@example.test', 'password' => 'SecurePassword123', 'roles' => ['manage'], 'permissions' => ['users.create'], 'emailVerified' => true]);

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->getTable())->toBe(AuthTables::Users)
        ->and(Hash::check('SecurePassword123', (string) $user->password))->toBeTrue()
        ->and($user->hasRole('manage'))->toBeTrue()
        ->and($user->hasDirectPermission('users.create'))->toBeTrue();

    $user->createToken('nvl-auth:mobile', ['users.create']);
    $disabled = app(AuthUsers::class)->setActive($actor, $user, ['active' => false]);

    expect($disabled->is_active)->toBeFalse()
        ->and($disabled->tokens()->count())->toBe(0)
        ->and(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'SecurePassword123'], [], auth()->guard('web'), app('session')->driver()))
        ->toThrow(AuthException::class, 'credentials');

    app(AuthUsers::class)->setActive($actor, $user, ['active' => true]);
    app(AuthRoles::class)->syncUserRoles($actor, $user, ['roles' => []]);
    app(AuthPermissions::class)->syncUserPermissions($actor, $user, ['permissions' => ['users.create']]);
    app(AuthUsers::class)->delete($actor, $user);

    expect($user->fresh()->trashed())->toBeTrue();

    $restored = app(AuthUsers::class)->restore($actor, $user->id);

    expect($restored->trashed())->toBeFalse()
        ->and($restored->is_active)->toBeTrue()
        ->and($restored->hasDirectPermission('users.create'))->toBeTrue();

    Event::assertDispatched(PrincipalChanged::class);
    Event::assertDispatched(RbacAssignmentChanged::class, 3);
});

it('supports profile, suggestions, and bounded bulk lifecycle operations', function (): void {
    $actor = $this->user('profile.owner@example.test');
    $first = app(AuthUsers::class)->create($actor, ['name' => 'Suggested Alpha', 'email' => 'alpha@example.test', 'password' => 'SecurePassword123']);
    $second = app(AuthUsers::class)->create($actor, ['name' => 'Suggested Beta', 'email' => 'beta@example.test', 'password' => 'SecurePassword123']);
    $first->forceFill(['remember_token' => 'first-remember'])->save();
    $second->forceFill(['remember_token' => 'second-remember'])->save();
    $first->createToken('nvl-auth:first', ['profile:read']);
    $second->createToken('nvl-auth:second', ['profile:read']);

    $profile = app(AuthUsers::class)->updateProfile($actor, ['name' => 'Updated Owner', 'locale' => 'bg', 'timezone' => 'Europe/Sofia', 'profile' => ['phone' => '+359000000000'], 'preferences' => ['theme' => 'dark']]);
    $suggestions = app(AuthUserReader::class)->suggest($actor, 'Suggested');
    $result = app(AuthUsers::class)->bulkUpdate(
        $actor,
        UserBulkOperation::Disable,
        [$first->id, $second->id],
    );

    expect($profile->name)->toBe('Updated Owner')
        ->and($profile->profile)->toBe(['phone' => '+359000000000'])
        ->and($profile->preferences)->toBe(['theme' => 'dark'])
        ->and($suggestions)->toHaveCount(2)
        ->and($result['affected'])->toBe(2)
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

    $shown = app(AuthUserReader::class)->find($actor, $first->id);
    $result = app(AuthUsers::class)->bulkUpdate(
        $actor,
        UserBulkOperation::Disable,
        [$first->id, $second->id],
    );

    expect($shown->is($first))->toBeTrue()
        ->and($result['affected'])->toBe(2)
        ->and($access->targets)->toHaveCount(3)
        ->and($access->targets)->each->toBeInstanceOf(User::class);
});

it('keeps eager-loaded principal list queries independent of fixture size', function (): void {
    $actor = $this->user('query-actor@example.test');
    $measure = function () use ($actor): int {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $page = app(AuthUserReader::class)->paginate($actor, perPage: 100);
        $queryCount = count(array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'from "nvl_auth_') && ! str_contains($query['query'], 'installation')));

        foreach ($page->items() as $user) {
            $user->roles->count();
            $user->permissions->count();
        }

        expect($queryCount)->toBeGreaterThan(0);
        expect(array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'from "nvl_auth_') && ! str_contains($query['query'], 'installation')))->toHaveCount($queryCount);
        DB::disableQueryLog();

        return $queryCount;
    };

    $this->user('query-user-1@example.test');
    $singleQueryCount = $measure();

    foreach (range(2, 25) as $index) {
        $this->user("query-user-{$index}@example.test");
    }

    $populatedQueryCount = $measure();

    expect($singleQueryCount)->toBeLessThanOrEqual(7)
        ->and($populatedQueryCount)->toBeLessThanOrEqual($singleQueryCount);
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
        $updated = app(AuthUsers::class)->setActive(
            new SystemMutationContext('Compliance failure', 'compliance-456', metadata: ['case' => '456']),
            $user,
            ['active' => false],
        );

        $audit = AuthAudit::query()->where('action', 'user.disabled')->firstOrFail();

        expect($updated->is_active)->toBeFalse()
            ->and($updated->remember_token)->not->toBe('remember-me')
            ->and($updated->tokens()->count())->toBe(0)
            ->and(DB::connection('testing')->table('sessions')->where('user_id', $user->id)->exists())->toBeFalse()
            ->and($audit->actor_id)->toBeNull()
            ->and($audit->metadata['system']['correlation_id'])->toBe('compliance-456');

        $reenabled = app(AuthUsers::class)->setActive(
            new SystemMutationContext('Compliance restored', 'compliance-456-restored'),
            $user,
            ['active' => true],
        );

        expect($reenabled->is_active)->toBeTrue();
    } finally {
        Schema::connection('testing')->dropIfExists('sessions');
    }
});

it('rejects invalid direct principal and RBAC input before persistence', function (): void {
    expect(fn () => app(AuthUsers::class)->create($this->user(), ['name' => 'Invalid Timezone', 'email' => 'invalid.timezone@example.test', 'password' => 'SecurePassword123', 'timezone' => 'Not/A-Timezone']))->toThrow(InvalidArgumentException::class, 'timezone')
        ->and(fn () => app(AuthRoles::class)->create($this->user('role-input@example.test'), ['name' => 'duplicated-permissions', 'permissions' => ['users.create', 'users.create']]))->toThrow(InvalidArgumentException::class, 'distinct');

    expect(User::query()->where('email', 'invalid.timezone@example.test')->exists())->toBeFalse();
});

it('changes self-service email sparsely after confirmation and restarts verification', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    Event::fake([AuthDeliveryRequested::class, PrincipalChanged::class]);
    $user = $this->user('old@example.test');
    $user->forceFill(['email_verified_at' => now(), 'locale' => 'bg'])->save();

    $updated = app(AuthUsers::class)->updateProfile($user, ['email' => ' New.Address@Example.Test '], grant: $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange, 'correct-password')->reveal(), context: $this->authenticationContext());

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

    $updated = app(AuthUsers::class)->updateProfile($user, ['name' => 'Updated Without Confirmation']);

    expect($updated->name)->toBe('Updated Without Confirmation')
        ->and($updated->email)->toBe('profile-name@example.test');
});

it('requires valid account confirmation before changing email', function (array $data, string $code): void {
    $user = $this->user('confirmation-required@example.test');
    $failure = null;

    try {
        app(AuthUsers::class)->updateProfile($user, $data);
    } catch (AuthException $exception) {
        $failure = $exception;
    }

    expect($failure)->toBeInstanceOf(AuthException::class)
        ->errorCode->toBe($code)
        ->and($user->refresh()->email)->toBe('confirmation-required@example.test');
})->with([
    'missing recent grant' => [
        ['email' => 'missing-confirmation@example.test'],
        'recent_authentication_required',
    ],
    'legacy password is no authority' => [
        ['email' => 'invalid-confirmation@example.test'],
        'recent_authentication_required',
    ],
]);

it('rejects a self-service email conflict without changing profile state', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    $user = $this->user('unchanged@example.test');
    $this->user('taken@example.test');

    expect(fn () => app(AuthUsers::class)->updateProfile($user, ['email' => 'taken@example.test'], grant: $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'unavailable')
        ->and($user->refresh()->email)->toBe('unchanged@example.test');
});

it('confirms, revokes credentials, and invalidates the session for self deletion', function (): void {
    $user = $this->user('self.delete@example.test');
    $user->createToken('nvl-auth:test', ['profile:read']);
    Auth::guard('web')->login($user);
    $request = app('request');
    $request->setLaravelSession(app('session')->driver());

    expect(app(AuthUsers::class)->deleteOwnAccount($user, [], auth()->guard('web'), app('session.store'), grant: $this->recentGrant($user, RecentAuthenticationPurpose::AccountDeletion, 'correct-password')->reveal(), context: $this->authenticationContext()))->toBeTrue()
        ->and(Auth::guard('web')->check())->toBeFalse()
        ->and($user->trashed())->toBeTrue()
        ->and($user->tokens()->count())->toBe(0);
});

<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\CentralAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;

uses(OwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

it('keeps same named roles and permission assignments in their admitted native owner', function (): void {
    $user = User::factory()->create();
    $actor = Actor::query()->findOrFail(1);
    $permission = Permission::query()->create(['name' => 'orders.read', 'guard_name' => 'web']);
    $runner = app(OwnershipRunner::class);
    $roles = [];
    foreach ([7, 8] as $key) {
        $roles[$key] = $runner->run(Company::query()->findOrFail($key), $actor, function () use ($user, $key): Role {
            app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'b-'.$key), SubjectReference::fromAuthenticatable($user));
            $role = app(AuthRoles::class)->create($user, ['name' => 'editor', 'permissions' => $key === 7 ? ['orders.read'] : []]);
            app(EloquentRbacPrincipalAccess::class)->assign($user, [$role->id], []);
            expect($user->fresh()->hasPermissionTo('orders.read'))->toBe($key === 7);

            return $role;
        });
    }
    expect($roles[7]->id)->not->toBe($roles[8]->id);
    $runner->run(Company::query()->findOrFail(7), $actor, function () use ($user, $roles): void {
        expect(Role::query()->find($roles[8]->id))->toBeNull()
            ->and($user->hasPermissionTo('orders.read'))->toBeTrue();
    });
});

it('requires the mutation actor to be admitted to the owner independently of the runner actor', function (): void {
    $outsider = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($outsider): void {
        expect(fn () => app(AuthRoles::class)->create($outsider, ['name' => 'outsider']))->toThrow(AuthException::class);
    });
});

it('limits permission inverse users and counts to active members of the current owner', function (): void {
    $user = User::factory()->create();
    $permission = Permission::query()->create(['name' => 'owned.direct', 'guard_name' => 'web']);
    foreach ([7, 8] as $key) {
        app(OwnershipRunner::class)->run(Company::query()->findOrFail($key), Actor::query()->findOrFail(1), function () use ($user, $permission, $key): void {
            app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'inverse-'.$key), SubjectReference::fromAuthenticatable($user));
            if ($key === 7) {
                app(EloquentRbacPrincipalAccess::class)->assign($user, [], [$permission->id]);
            }
            expect($permission->fresh()->users()->count())->toBe($key === 7 ? 1 : 0);
        });
    }
});

it('rejects unpartitioned pivots and cross-owner role links at the database boundary', function (): void {
    $user = User::factory()->create();
    $runner = app(OwnershipRunner::class);
    $actor = Actor::query()->findOrFail(1);
    $foreign = Company::query()->findOrFail(8);
    $parent = $runner->run(Company::query()->findOrFail(7), $actor, fn () => Role::query()->create(['name' => 'parent', 'guard_name' => 'web']));
    $child = $runner->run($foreign, $actor, fn () => Role::query()->create(['name' => 'child', 'guard_name' => 'web']));
    $owner = app(OwnerIdentityResolver::class)->reference($foreign);
    foreach ([null, $owner->scopeKey()] as $scope) {
        expect(fn () => DB::table('nvl_auth_model_has_roles')->insert([
            'role_id' => $parent->id, 'model_type' => $user->getMorphClass(), 'model_id' => $user->id, 'owner_scope_key' => $scope,
        ]))->toThrow(QueryException::class);
    }
    expect(fn () => DB::table($child->getTable())->where('id', $child->id)->update(['parent_id' => $parent->id]))->toThrow(QueryException::class);
});

it('keeps central roles and grants out of every owner permission map', function (): void {
    $user = User::factory()->create();
    Permission::query()->create(['name' => 'central.only', 'guard_name' => 'web']);
    config(['nvl-ownership.central_operations' => ['auth-rbac']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });
    $runner = app(OwnershipRunner::class);
    $runner->central('auth-rbac', Actor::query()->findOrFail(1), function () use ($user): void {
        $role = app(AuthRoles::class)->create($user, ['name' => 'global-administrator', 'permissions' => ['central.only']]);
        app(EloquentRbacPrincipalAccess::class)->assign($user, [$role->id], []);
        expect($user->hasPermissionTo('central.only'))->toBeTrue();
    });
    $runner->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'central-role'), SubjectReference::fromAuthenticatable($user));
        expect($user->hasPermissionTo('central.only'))->toBeFalse();
    });
});

it('clears retained principal grants immediately when its membership is revoked', function (): void {
    $admin = User::factory()->create();
    $member = User::factory()->create();
    $permission = Permission::query()->create(['name' => 'retained.read', 'guard_name' => 'web']);
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $member, $permission): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'cached-revocation'), SubjectReference::fromAuthenticatable($admin));
        $membership = app(AuthMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($member), [], [$permission->id]);
        expect($member->hasPermissionTo('retained.read'))->toBeTrue();
        app(AuthMemberships::class)->setStatus($admin, $membership, MembershipStatus::Revoked, $membership->revision);
        expect($member->hasPermissionTo('retained.read'))->toBeFalse();
    });
});

it('refreshes warmed owner permission maps after central catalog mutations', function (string $mutation, bool $nested): void {
    $user = User::factory()->create();
    $actor = Actor::query()->findOrFail(1);
    $permission = Permission::query()->create(['name' => 'orders.read', 'guard_name' => 'web']);
    $runner = app(OwnershipRunner::class);
    config(['nvl-ownership.central_operations' => ['auth-rbac']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });

    foreach ([7, 8] as $key) {
        $runner->run(Company::query()->findOrFail($key), $actor, function () use ($user, $key): void {
            app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'cache-'.$key), SubjectReference::fromAuthenticatable($user));
            $role = app(AuthRoles::class)->create($user, ['name' => 'reader', 'permissions' => ['orders.read']]);
            app(EloquentRbacPrincipalAccess::class)->assign($user, [$role->id], []);
            expect($user->fresh()->checkPermissionTo('orders.read'))->toBeTrue();
        });
    }

    $change = function () use ($runner, $actor, $user, $permission, $mutation): void {
        $runner->central('auth-rbac', $actor, function () use ($user, $permission, $mutation): void {
            if ($mutation === 'rename') {
                app(AuthPermissions::class)->update($user, $permission, ['name' => 'orders.changed']);
            } else {
                app(AuthPermissions::class)->delete($user, $permission);
            }
        });
    };

    if ($nested) {
        $runner->run(Company::query()->findOrFail(7), $actor, function () use ($user, $change): void {
            expect($user->fresh()->checkPermissionTo('orders.read'))->toBeTrue();
            $change();
            expect($user->fresh()->checkPermissionTo('orders.read'))->toBeFalse();
        });
    } else {
        $change();
    }

    foreach ([7, 8] as $key) {
        $runner->run(Company::query()->findOrFail($key), $actor, function () use ($user, $mutation): void {
            expect($user->fresh()->checkPermissionTo('orders.read'))->toBeFalse();
            if ($mutation === 'rename') {
                expect($user->fresh()->checkPermissionTo('orders.changed'))->toBeTrue();
            }
        });
    }
})->with(['rename', 'delete'])->with(['subsequent scope' => false, 'restored scope' => true]);

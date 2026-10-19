<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\CentralAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;

uses(OwnerScopeTestCase::class);

it('keeps same named roles and permission assignments in their admitted native owner', function (): void {
    $user = User::factory()->create();
    $actor = Actor::query()->findOrFail(1);
    $permission = Permission::query()->create(['name' => 'orders.read', 'guard_name' => 'web']);
    $runner = app(OwnershipRunner::class);
    $roles = [];
    foreach ([7, 8] as $key) {
        $roles[$key] = $runner->run(Company::query()->findOrFail($key), $actor, function () use ($user, $key): Role {
            app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'b-'.$key), SubjectReference::fromAuthenticatable($user));
            $role = app(CreateRoleAction::class)->execute($user, new StoreRoleData('editor', permissions: $key === 7 ? ['orders.read'] : []));
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
        expect(fn () => app(CreateRoleAction::class)->execute($outsider, new StoreRoleData('outsider')))->toThrow(AuthException::class);
    });
});

it('limits permission inverse users and counts to active members of the current owner', function (): void {
    $user = User::factory()->create();
    $permission = Permission::query()->create(['name' => 'owned.direct', 'guard_name' => 'web']);
    foreach ([7, 8] as $key) {
        app(OwnershipRunner::class)->run(Company::query()->findOrFail($key), Actor::query()->findOrFail(1), function () use ($user, $permission, $key): void {
            app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'inverse-'.$key), SubjectReference::fromAuthenticatable($user));
            if ($key === 7) {
                app(EloquentRbacPrincipalAccess::class)->assign($user, [], [$permission->id]);
            }
            expect($permission->fresh()->users()->count())->toBe($key === 7 ? 1 : 0);
        });
    }
});

it('rejects unpartitioned and foreign-role pivot writes at the database boundary', function (): void {
    $user = User::factory()->create();
    $role = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => Role::query()->create(['name' => 'locked', 'guard_name' => 'web']));
    $owner = app(OwnerIdentityResolver::class)->reference(Company::query()->findOrFail(8));
    foreach ([null, $owner->scopeKey()] as $scope) {
        expect(fn () => DB::table('nvl_auth_model_has_roles')->insert([
            'role_id' => $role->id, 'model_type' => $user->getMorphClass(), 'model_id' => $user->id, 'owner_scope_key' => $scope,
        ]))->toThrow(QueryException::class);
    }
});

it('rejects a role hierarchy edge to a different owner at the database boundary', function (): void {
    $parent = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => Role::query()->create(['name' => 'parent', 'guard_name' => 'web']));
    $child = app(OwnershipRunner::class)->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), fn () => Role::query()->create(['name' => 'child', 'guard_name' => 'web']));
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
        $role = app(CreateRoleAction::class)->execute($user, new StoreRoleData('global-administrator', permissions: ['central.only']));
        app(EloquentRbacPrincipalAccess::class)->assign($user, [$role->id], []);
        expect($user->hasPermissionTo('central.only'))->toBeTrue();
    });
    $runner->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'central-role'), SubjectReference::fromAuthenticatable($user));
        expect($user->hasPermissionTo('central.only'))->toBeFalse();
    });
});

it('clears retained principal grants immediately when its membership is revoked', function (): void {
    $admin = User::factory()->create();
    $member = User::factory()->create();
    $permission = Permission::query()->create(['name' => 'retained.read', 'guard_name' => 'web']);
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $member, $permission): void {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'cached-revocation'), SubjectReference::fromAuthenticatable($admin));
        $membership = app(OwnerMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($member), [], [$permission->id]);
        expect($member->hasPermissionTo('retained.read'))->toBeTrue();
        app(OwnerMemberships::class)->setStatus($admin, $membership, MembershipStatus::Revoked, $membership->revision);
        expect($member->hasPermissionTo('retained.read'))->toBeFalse();
    });
});

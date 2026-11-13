<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\QueryException;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\CentralAccess;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

uses(OwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

it('protects the last owner and revalidates membership revocation on entry', function (): void {
    $user = TestUser::factory()->create();
    $other = TestUser::factory()->create();
    $company = Company::query()->findOrFail(7);
    $actor = Actor::query()->findOrFail(1);
    $memberships = app(AuthMemberships::class);
    $authority = new SystemMutationContext('reviewed bootstrap', 'b');
    app(OwnershipRunner::class)->run($company, $actor, function () use ($memberships, $authority, $user, $other): void {
        $first = $memberships->provision($authority, SubjectReference::fromAuthenticatable($user));
        expect(fn () => $memberships->setStatus($authority, $first, MembershipStatus::Revoked, $first->revision))->toThrow(AuthException::class);
        $memberships->provision($authority, SubjectReference::fromAuthenticatable($other));
        $memberships->setStatus($authority, $first, MembershipStatus::Revoked, $first->revision);
    });
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    expect(fn () => app(OwnershipRunner::class)->run($company, $user, static fn () => true))->toThrow(AuthException::class);
    expect(app(OwnershipRunner::class)->run($company, $other, static fn () => true))->toBeTrue();
});

it('requires native owner admission before provisioning and managing memberships', function (): void {
    $owners = Company::query()->count();
    $admin = TestUser::factory()->create();
    expect(fn () => app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'unadmitted'), SubjectReference::fromAuthenticatable($admin)))
        ->toThrow(OwnershipViolation::class)
        ->and(Company::query()->count())->toBe($owners)
        ->and(TestUser::query()->count())->toBe(1);
    $recipient = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $recipient): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'actions'), SubjectReference::fromAuthenticatable($admin));
        $membership = app(AuthMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($recipient));
        expect($membership)->toBeInstanceOf(OwnerMembership::class)
            ->and(app(AuthMemberships::class)->paginate($admin)->total())->toBe(2)
            ->and(app(AuthMemberships::class)->find($admin, $membership)->subject_id)->toBe($recipient->id);
        app(AuthMemberships::class)->revoke($admin, $membership, $membership->revision);
        expect(app(AuthMemberships::class)->find(TestUser::query()->firstOrFail(), $membership)->status)->toBe(MembershipStatus::Revoked);
    });
});

it('creates native membership fixtures without accessing legacy membership tables', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $membership = OwnerMembership::factory()->create(['subject_type' => $user->getMorphClass(), 'subject_id' => $user->id]);
        expect($membership)->toBeInstanceOf(OwnerMembership::class)
            ->and($membership->getTable())->toBe('nvl_auth_owner_memberships');
    });
});

it('transfers owner administration inside one native owner and exposes only the subjects own discovery', function (): void {
    $first = TestUser::factory()->create();
    $second = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($first, $second): void {
        $source = app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'transfer'), SubjectReference::fromAuthenticatable($first));
        $target = app(AuthMemberships::class)->enroll($first, SubjectReference::fromAuthenticatable($second));
        app(AuthMemberships::class)->transfer($first, $source, $target->id, $source->revision);
        expect(app(AuthMemberships::class)->find(TestUser::query()->firstOrFail(), $source)->is_owner)->toBeFalse()
            ->and(app(AuthMemberships::class)->find(TestUser::query()->firstOrFail(), $target)->is_owner)->toBeTrue();
    });
    $own = app(AuthMemberships::class)->own($second);
    expect($own)->toHaveCount(1)->and($own->first()['owner']['key'])->toBe('7');
});

it('protects native last-owner responsibility when the global principal is disabled', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'global'), SubjectReference::fromAuthenticatable($user)));
    config(['nvl-ownership.central_operations' => ['auth-principals']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });
    expect(fn () => app(OwnershipRunner::class)->central('auth-principals', Actor::query()->findOrFail(1), fn () => app(AuthUsers::class)->setActive(new SystemMutationContext('disable', 'global'), $user, ['active' => false])))->toThrow(AuthException::class);
    expect($user->fresh()->is_active)->toBeTrue();
});

it('contains all owner-bound credentials during authorized global principal disable', function (): void {
    $admin = TestUser::factory()->create();
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $user): void {
        app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'contain'), SubjectReference::fromAuthenticatable($admin));
        app(AuthMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($user));
        app(AuthTokens::class)->create($user, ['name' => 'owner-token', 'abilities' => ['profile:read']]);
    });
    config(['nvl-ownership.central_operations' => ['auth-principals']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });
    $disabled = app(OwnershipRunner::class)->central('auth-principals', Actor::query()->findOrFail(1), fn () => app(AuthUsers::class)->setActive(new SystemMutationContext('disable', 'contain'), $user, ['active' => false]));
    expect($disabled->is_active)->toBeFalse()
        ->and((new PersonalAccessToken)->getConnection()->table('nvl_auth_personal_access_tokens')->where('tokenable_id', $user->id)->count())->toBe(0);
});

it('persists membership lifecycle audits with their owning transaction', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $connection = (new OwnerMembership)->getConnection();
        try {
            $connection->transaction(function () use ($user): void {
                app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'audit-rollback'), SubjectReference::fromAuthenticatable($user));
                expect(AuthAudit::query()->where('action', 'membership.owner_provisioned')->count())->toBe(1);
                throw new RuntimeException('rollback');
            });
        } catch (RuntimeException $exception) {
            expect($exception->getMessage())->toBe('rollback');
        }
        expect(AuthAudit::query()->where('action', 'membership.owner_provisioned')->count())->toBe(0)
            ->and(OwnerMembership::query()->count())->toBe(0);
    });
});

it('prevents relabeling an existing membership to a different principal', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $membership = app(AuthMemberships::class)->provision(new SystemMutationContext('bootstrap', 'immutable-subject'), SubjectReference::fromAuthenticatable($user));
        expect(fn () => $membership->getConnection()->table($membership->getTable())->where('id', $membership->id)->update(['subject_id' => 'foreign-principal']))
            ->toThrow(QueryException::class);
    });
});

it('requires access management authority before enrollment grants or replaces member access', function (): void {
    $admin = TestUser::factory()->create();
    $member = TestUser::factory()->create();
    $this->app->bind(AuthManagementAccess::class, static fn () => new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return $ability !== 'nvl.auth.memberships.manageAccess';
        }
    });
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $member): void {
        $memberships = app(AuthMemberships::class);
        $system = new SystemMutationContext('bootstrap', 'manage-access');
        $reference = SubjectReference::fromAuthenticatable($member);
        $memberships->provision($system, SubjectReference::fromAuthenticatable($admin));
        $role = app(AuthRoles::class)->create($admin, ['name' => 'tenant-admin']);

        expect(fn () => $memberships->enroll($admin, $reference, [$role->id]))->toThrow(AuthException::class, 'not authorized')
            ->and(OwnerMembership::query()->where('subject_id', $member->id)->exists())->toBeFalse();

        $memberships->enroll($admin, $reference);
        $memberships->enroll($system, $reference, [$role->id]);
        expect($member->fresh()->hasRole('tenant-admin'))->toBeTrue()
            ->and(fn () => $memberships->enroll($admin, $reference))->toThrow(AuthException::class, 'not authorized')
            ->and(fn () => $memberships->enroll($admin, SubjectReference::fromAuthenticatable($admin), [$role->id]))->toThrow(AuthException::class, 'not authorized')
            ->and($member->fresh()->hasRole('tenant-admin'))->toBeTrue()
            ->and($admin->fresh()->hasRole('tenant-admin'))->toBeFalse();
    });
});

it('does not restore owner administration when a revoked owner membership is reactivated', function (): void {
    $first = TestUser::factory()->create();
    $second = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($first, $second): void {
        $memberships = app(AuthMemberships::class);
        $system = new SystemMutationContext('bootstrap', 'revoked-owner');
        $former = $memberships->provision($system, SubjectReference::fromAuthenticatable($first));
        $memberships->provision($system, SubjectReference::fromAuthenticatable($second));
        $revoked = $memberships->revoke($second, $former, $former->revision);
        $reactivated = $memberships->setStatus($second, $revoked, MembershipStatus::Active, $revoked->revision);

        expect($revoked->is_owner)->toBeFalse()
            ->and($reactivated->status)->toBe(MembershipStatus::Active)
            ->and($reactivated->is_owner)->toBeFalse();
    });
});

it('refuses to transfer owner administration to suspended or revoked memberships', function (): void {
    $owner = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($owner): void {
        $memberships = app(AuthMemberships::class);
        $source = $memberships->provision(new SystemMutationContext('bootstrap', 'inactive-transfer'), SubjectReference::fromAuthenticatable($owner));
        foreach ([MembershipStatus::Suspended, MembershipStatus::Revoked] as $status) {
            $recipient = TestUser::factory()->create();
            $target = $memberships->enroll($owner, SubjectReference::fromAuthenticatable($recipient));
            $target = $memberships->setStatus($owner, $target, $status, $target->revision);

            expect(fn () => $memberships->transfer($owner, $source, $target->id, $source->revision))->toThrow(AuthException::class, 'cannot be transferred')
                ->and($memberships->find($owner, $target)->status)->toBe($status, $status->value)
                ->and($memberships->find($owner, $target)->is_owner)->toBeFalse()
                ->and($memberships->find($owner, $source)->is_owner)->toBeTrue();
        }
    });
});

it('matches membership search text literally instead of as LIKE wildcards', function (): void {
    $admin = TestUser::factory()->create();
    $member = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $member): void {
        $memberships = app(AuthMemberships::class);
        $memberships->provision(new SystemMutationContext('bootstrap', 'search'), SubjectReference::fromAuthenticatable($admin));
        $memberships->enroll($admin, SubjectReference::fromAuthenticatable($member));

        expect($memberships->paginate($admin, substr($member->id, 0, 13))->total())->toBe(1)
            ->and($memberships->paginate($admin, '%')->total())->toBe(0)
            ->and($memberships->paginate($admin, '_')->total())->toBe(0);
    });
});

it('refuses another owner roles and memberships in every membership mutation and RBAC read', function (): void {
    $admin = TestUser::factory()->create();
    $member = TestUser::factory()->create();
    $system = new SystemMutationContext('bootstrap', 'cross-owner');
    $runner = app(OwnershipRunner::class);
    [$foreignRole, $foreignMembership, $foreignAdmin] = $runner->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), function () use ($admin, $member, $system): array {
        $owner = app(AuthMemberships::class)->provision($system, SubjectReference::fromAuthenticatable($admin));

        return [app(AuthRoles::class)->create($admin, ['name' => 'foreign-admin']), app(AuthMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($member)), $owner];
    });
    $runner->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $member, $system, $foreignRole, $foreignMembership, $foreignAdmin): void {
        $memberships = app(AuthMemberships::class);
        $source = $memberships->provision($system, SubjectReference::fromAuthenticatable($admin));
        $reader = app(AuthRbacReader::class);

        expect($source->id)->not->toBe($foreignAdmin->id)
            ->and($memberships->find($admin, $source->id)->subject_id)->toBe($admin->id)
            ->and(fn () => $memberships->find($admin, $foreignAdmin->id))->toThrow(OwnershipViolation::class);

        expect(fn () => $memberships->enroll($admin, SubjectReference::fromAuthenticatable($member), [$foreignRole->id]))->toThrow(AuthException::class, 'assignment is invalid')
            ->and(fn () => $memberships->enroll($admin, SubjectReference::fromAuthenticatable($member), ['foreign-admin']))->toThrow(AuthException::class, 'assignment is invalid')
            ->and(OwnerMembership::query()->where('subject_id', $member->id)->exists())->toBeFalse()
            ->and(fn () => $memberships->setStatus($admin, $foreignMembership->id, MembershipStatus::Suspended, $foreignMembership->revision))->toThrow(OwnershipViolation::class)
            ->and(fn () => $memberships->revoke($admin, $foreignMembership->id, $foreignMembership->revision))->toThrow(OwnershipViolation::class)
            ->and(fn () => $memberships->transfer($admin, $source, $foreignMembership->id, $source->revision))->toThrow(OwnershipViolation::class)
            ->and($reader->roles($admin, 'foreign')->total())->toBe(0)
            ->and($reader->roleOptions($admin, 'foreign'))->toHaveCount(0)
            ->and(fn () => $reader->role($admin, $foreignRole->id))->toThrow(ModelNotFoundException::class);
    });
    $runner->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), function () use ($admin, $foreignMembership): void {
        expect(app(AuthMemberships::class)->find($admin, $foreignMembership->id)->status)->toBe(MembershipStatus::Active);
    });
});

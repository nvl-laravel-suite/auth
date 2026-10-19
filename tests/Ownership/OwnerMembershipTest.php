<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\Memberships\EnrollMembershipAction;
use Nvl\Auth\Actions\Memberships\ListMembershipsAction;
use Nvl\Auth\Actions\Memberships\ListOwnMembershipsAction;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Actions\Memberships\ShowMembershipAction;
use Nvl\Auth\Actions\Memberships\TransferMembershipOwnershipAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Data\Mutations\EnrollMembershipData;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Data\Mutations\UpdateUserStatusData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\CentralAccess;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

uses(OwnerScopeTestCase::class);

it('keeps one principal memberships separate in native owners seven and eight', function (): void {
    $user = TestUser::factory()->create();
    $memberships = app(OwnerMemberships::class);
    $runner = app(OwnershipRunner::class);
    $actor = Actor::query()->findOrFail(1);
    $authority = new SystemMutationContext('reviewed bootstrap', 'bootstrap-1');
    $ids = [];
    foreach ([7, 8] as $key) {
        $ids[] = $runner->run(Company::query()->findOrFail($key), $actor, fn () => $memberships->provision($authority, SubjectReference::fromAuthenticatable($user))->id);
    }
    expect($ids[0])->not->toBe($ids[1]);
    $runner->run(Company::query()->findOrFail(7), $actor, function () use ($memberships, $ids, $user): void {
        expect($memberships->find($ids[0])->subject_id)->toBe($user->id)
            ->and(fn () => $memberships->find($ids[1]))->toThrow(OwnershipViolation::class);
    });
});

it('denies enrollment without an admitted owner and never creates owners or credentials', function (): void {
    $before = Company::query()->count();
    $user = TestUser::factory()->create();
    expect(fn () => app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'b'), SubjectReference::fromAuthenticatable($user)))
        ->toThrow(OwnershipViolation::class)
        ->and(Company::query()->count())->toBe($before)
        ->and(TestUser::query()->count())->toBe(1);
});

it('protects the last owner and revalidates membership revocation on entry', function (): void {
    $user = TestUser::factory()->create();
    $other = TestUser::factory()->create();
    $company = Company::query()->findOrFail(7);
    $actor = Actor::query()->findOrFail(1);
    $memberships = app(OwnerMemberships::class);
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

it('uses ownership through the existing membership Actions', function (): void {
    $admin = TestUser::factory()->create();
    $recipient = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $recipient): void {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'actions'), SubjectReference::fromAuthenticatable($admin));
        $membership = app(EnrollMembershipAction::class)->execute($admin, new EnrollMembershipData(SubjectReference::fromAuthenticatable($recipient)));
        expect($membership)->toBeInstanceOf(OwnerMembership::class)
            ->and(app(ListMembershipsAction::class)->execute($admin)->total())->toBe(2)
            ->and(app(ShowMembershipAction::class)->execute($admin, $membership)->subjectId)->toBe($recipient->id);
        app(RevokeMembershipAction::class)->execute($admin, $membership, $membership->revision);
        expect(app(OwnerMemberships::class)->find($membership)->status)->toBe(MembershipStatus::Revoked);
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
        $source = app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'transfer'), SubjectReference::fromAuthenticatable($first));
        $target = app(OwnerMemberships::class)->enroll($first, SubjectReference::fromAuthenticatable($second));
        app(TransferMembershipOwnershipAction::class)->execute($first, $source, new TransferMembershipOwnershipData($target->id, $source->revision));
        expect(app(OwnerMemberships::class)->find($source)->is_owner)->toBeFalse()
            ->and(app(OwnerMemberships::class)->find($target)->is_owner)->toBeTrue();
    });
    $own = app(ListOwnMembershipsAction::class)->execute($second);
    expect($own)->toHaveCount(1)->and($own->first()['owner']['key'])->toBe('7');
});

it('protects native last-owner responsibility when the global principal is disabled', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'global'), SubjectReference::fromAuthenticatable($user)));
    config(['nvl-ownership.central_operations' => ['auth-principals']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });
    expect(fn () => app(OwnershipRunner::class)->central('auth-principals', Actor::query()->findOrFail(1), fn () => app(SetUserActiveAction::class)->execute(new SystemMutationContext('disable', 'global'), $user, new UpdateUserStatusData(false))))->toThrow(AuthException::class);
    expect($user->fresh()->is_active)->toBeTrue();
});

it('contains all owner-bound credentials during authorized global principal disable', function (): void {
    $admin = TestUser::factory()->create();
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($admin, $user): void {
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'contain'), SubjectReference::fromAuthenticatable($admin));
        app(OwnerMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($user));
        app(CreateApiTokenAction::class)->execute($user, new ApiTokenData('owner-token', ['profile:read']));
    });
    config(['nvl-ownership.central_operations' => ['auth-principals']]);
    $this->app->bind(CentralAccess::class, static fn () => new class implements CentralAccess
    {
        public function assertCanRun(string $operation, Authenticatable $actor): void {}
    });
    $disabled = app(OwnershipRunner::class)->central('auth-principals', Actor::query()->findOrFail(1), fn () => app(SetUserActiveAction::class)->execute(new SystemMutationContext('disable', 'contain'), $user, new UpdateUserStatusData(false)));
    expect($disabled->is_active)->toBeFalse()
        ->and((new PersonalAccessToken)->getConnection()->table('nvl_auth_personal_access_tokens')->where('tokenable_id', $user->id)->count())->toBe(0);
});

it('persists membership lifecycle audits with their owning transaction', function (): void {
    $user = TestUser::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $connection = (new OwnerMembership)->getConnection();
        try {
            $connection->transaction(function () use ($user): void {
                app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'audit-rollback'), SubjectReference::fromAuthenticatable($user));
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
        $membership = app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'immutable-subject'), SubjectReference::fromAuthenticatable($user));
        expect(fn () => $membership->getConnection()->table($membership->getTable())->where('id', $membership->id)->update(['subject_id' => 'foreign-principal']))
            ->toThrow(QueryException::class);
    });
});

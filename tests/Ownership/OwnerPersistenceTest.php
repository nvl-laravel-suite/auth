<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Tests\Fixtures\AuthMembershipRace;
use Nvl\Auth\Tests\Fixtures\Ownership\MembershipProbeJob;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\Queue\QueueScenario;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;
use Symfony\Component\Process\Process;

uses(OwnerScopeTestCase::class);

it('serializes competing native last-owner removals on independent connections', function (): void {
    if (getenv('NVL_OWNERSHIP_TEST_DRIVER') !== 'pgsql' || ! function_exists('pcntl_fork')) {
        $this->markTestSkipped('Requires dedicated PostgreSQL sources and independent forked connections.');
    }
    $authority = new SystemMutationContext('race', 'native-last-owner');
    $ids = app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($authority): array {
        return array_map(static fn (User $user): string => app(OwnerMemberships::class)->provision($authority, SubjectReference::fromAuthenticatable($user))->id, User::factory()->count(2)->create()->all());
    });
    $results = AuthMembershipRace::run('sqlite', array_map(static fn (string $id): Closure => static function () use ($id, $authority): array {
        app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), fn () => app(OwnerMemberships::class)->setStatus($authority, $id, MembershipStatus::Revoked, 1));

        return ['removed' => $id];
    }, $ids));
    DB::purge('sqlite');
    expect(array_column($results, 'ok'))->toContain(true, false)
        ->and(array_column(array_filter($results, static fn (array $result): bool => ! $result['ok']), 'code'))->toBe(['membership_last_owner'])
        ->and(DB::table((new OwnerMembership)->getTable())->where('status', 'active')->where('is_owner', true)->count())->toBe(1);
});

it('rechecks native membership before command restoration in a separate worker process', function (): void {
    if (getenv('NVL_OWNERSHIP_TEST_DRIVER') !== 'pgsql') {
        $this->markTestSkipped('Requires explicitly dedicated PostgreSQL persistence sources.');
    }
    QueueScenario::install();
    $subject = User::factory()->create();
    $admin = User::factory()->create();
    $memberships = [];
    foreach ([7, 8] as $key) {
        $memberships[$key] = app(OwnershipRunner::class)->run(Company::query()->findOrFail($key), Actor::query()->findOrFail(1), function () use ($subject, $admin, $key): OwnerMembership {
            app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'worker-'.$key), SubjectReference::fromAuthenticatable($admin));

            return app(OwnerMemberships::class)->enroll($admin, SubjectReference::fromAuthenticatable($subject));
        });
    }
    $this->app->bind(OwnerAccess::class, AuthOwnerAccess::class);
    foreach ([7, 8] as $key) {
        app(OwnershipRunner::class)->run(Company::query()->findOrFail($key), $subject, function () use ($memberships, $key): void {
            Queue::connection('database')->push(new MembershipProbeJob(OwnershipJobEnvelope::capture(app(OwnershipContext::class)), $memberships[$key]->id, 'owner-'.$key));
        });
    }
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), $admin, fn () => app(OwnerMemberships::class)->setStatus($admin, $memberships[7], MembershipStatus::Revoked, 1));
    $process = new Process([PHP_BINARY, __DIR__.'/../Fixtures/Ownership/worker.php', json_encode(config('database.connections.sqlite'), JSON_THROW_ON_ERROR)], timeout: 40);
    $process->mustRun();
    expect($process->getOutput())->toBe('auth-worker-complete')
        ->and(DB::table('jobs')->count())->toBe(0)
        ->and(DB::table('ownership_queue_probes')->where('label', 'owner-7')->count())->toBe(0)
        ->and(DB::table('ownership_queue_probes')->where('stage', 'auth-restore')->where('label', 'owner-8')->value('owner'))->toBe('8')
        ->and(DB::table('ownership_queue_probes')->where('stage', 'auth-handle')->where('label', 'owner-8')->value('owner'))->toBe('8')
        ->and(DB::table('ownership_queue_probes')->where('stage', 'auth-worker-after')->where('owner', '<>', 'unresolved')->count())->toBe(0)
        ->and(DB::table('failed_jobs')->count())->toBe(1);
});

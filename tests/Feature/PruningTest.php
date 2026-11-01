<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\ValueObjects\SystemMutationContext;

it('commits bounded retention batches using one cutoff and exact deletion counts', function (): void {
    config(['nvl-auth.cleanup.retention_days' => 30, 'nvl-auth.cleanup.batch_size' => 2]);
    $this->travelTo(now()->startOfSecond());
    $cutoff = now()->subDays(30);
    Invitation::factory()->count(5)->create(['expires_at' => $cutoff->copy()->subDay()]);
    $retained = Invitation::factory()->create(['expires_at' => $cutoff->copy()->addDay()]);
    $boundary = Invitation::factory()->create(['expires_at' => $cutoff]);
    $connection = (new Invitation)->getConnection();
    $driver = getenv('NVL_C1_TEST_DRIVER');
    if (in_array($driver, ['pgsql', 'mysql', 'mariadb'], true)) {
        expect($connection->getDriverName())->toBe($driver)
            ->and($connection->getPdo()->getAttribute(PDO::ATTR_DRIVER_NAME))->toBe($driver === 'pgsql' ? 'pgsql' : 'mysql');
    }
    expect($connection->transactionLevel())->toBe(0);
    $deletes = [];
    $committed = 0;
    $connection->listen(function (QueryExecuted $query) use (&$deletes, &$committed, $connection): void {
        if (! str_starts_with(strtolower($query->sql), 'delete from '.$connection->getQueryGrammar()->wrapTable((new Invitation)->getTable()))) {
            return;
        }
        $deletes[] = ['bindings' => $query->bindings, 'committed_before' => $committed];
        $connection->afterCommit(function () use (&$committed): void {
            $committed++;
        });
        $this->travel(3)->days();
    });
    try {
        $counts = app(AuthMaintenance::class)->prune(new SystemMutationContext('Bounded retention', 'prune-batches'));
        expect($counts['invitations'])->toBe(5)->and($deletes)->toHaveCount(3)
            ->and(array_column($deletes, 'committed_before'))->toBe([0, 1, 2])
            ->and($committed)->toBe(3)
            ->and(Invitation::query()->pluck('id')->sort()->values()->all())->toBe(collect([$retained->identifier(), $boundary->identifier()])->sort()->values()->all());
        foreach ($deletes as $delete) {
            $identifiers = array_filter($delete['bindings'], static fn (mixed $binding): bool => is_string($binding) && preg_match('/^[a-f0-9-]{36}$/D', $binding) === 1);
            expect(count($identifiers))->toBeGreaterThan(0)->toBeLessThanOrEqual(2);
        }
    } finally {
        $this->travelBack();
    }
});

it('stops a later retention batch when fresh system authorization is revoked', function (): void {
    config(['nvl-auth.cleanup.batch_size' => 2]);
    Invitation::factory()->count(5)->create(['expires_at' => now()->subDays(40)]);
    $policy = new class implements SystemMutationAccess
    {
        public int $calls = 0;

        public function allows(SystemMutationContext $context, string $ability, mixed $target = null): bool
        {
            return ++$this->calls <= 4;
        }
    };
    app()->instance(SystemMutationAccess::class, $policy);

    expect(fn () => app(AuthMaintenance::class)->prune(new SystemMutationContext('Revocable retention', 'prune-revocation')))
        ->toThrow(AuthException::class, 'not authorized')
        ->and(Invitation::query()->count())->toBe(3);
});

it('rechecks terminal predicates when a selected retention record is renewed before deletion', function (): void {
    config(['nvl-auth.cleanup.batch_size' => 2]);
    Invitation::factory()->count(5)->create(['expires_at' => now()->subDays(40)]);
    $renewed = Invitation::query()->orderBy('id')->firstOrFail();
    $connection = $renewed->getConnection();
    $changed = false;
    $prefix = 'select '.$connection->getQueryGrammar()->wrap($renewed->getQualifiedKeyName());
    $connection->listen(function (QueryExecuted $query) use (&$changed, $prefix, $renewed): void {
        if (! $changed && str_starts_with(strtolower($query->sql), $prefix)) {
            $changed = true;
            $renewed->forceFill(['expires_at' => now()->addDay()])->save();
        }
    });

    $counts = app(AuthMaintenance::class)->prune(new SystemMutationContext('Predicate retention', 'prune-predicates'));

    expect($changed)->toBeTrue()->and($counts['invitations'])->toBe(4)
        ->and(Invitation::query()->get()->modelKeys())->toBe([$renewed->identifier()]);
});

it('counts retention previews on the authoritative write source instead of a lagging read PDO', function (): void {
    Invitation::factory()->create(['expires_at' => now()->subDays(40)]);
    $connection = (new Invitation)->getConnection();
    $read = $connection->getReadPdo();
    $modified = $connection->hasModifiedRecords();
    $connection->setRecordModificationState(false);
    $connection->setReadPdo(new PDO('sqlite::memory:'));
    try {
        expect(app(AuthMaintenance::class)->prune(new SystemMutationContext('Primary retention preview', 'prune-primary'), true)['invitations'])->toBe(1);
    } finally {
        $connection->setReadPdo($read);
        $connection->setRecordModificationState($modified);
    }
});

it('documents and enforces the default denied system authorization for scheduled pruning', function (): void {
    expect(Artisan::call('help', ['command_name' => 'nvl:auth:prune']))->toBe(0)
        ->and(Artisan::output())->toContain('SystemMutationAccess');
    Invitation::factory()->create(['expires_at' => now()->subDays(40)]);
    app()->instance(SystemMutationAccess::class, new DenySystemMutationAccess);

    expect(fn () => Artisan::call('nvl:auth:prune', ['--dry-run' => true]))->toThrow(AuthException::class, 'not authorized')
        ->and(Invitation::query()->count())->toBe(1);
});

it('dry-runs and prunes only old terminal state while retaining audits', function (): void {
    config()->set('nvl-auth.cleanup.retention_days', 30);
    $invitation = Invitation::factory()->create([
        'expires_at' => now()->subDays(40),
        'created_at' => now()->subDays(40),
        'updated_at' => now()->subDays(40),
    ]);
    $passkey = Passkey::factory()->create(['revoked_at' => now()->subDays(40)]);
    $audit = AuthAudit::factory()->create(['created_at' => now()->subDays(100)]);
    $action = app(AuthMaintenance::class);

    expect($action->prune(new SystemMutationContext('Retention cleanup', 'prune-test'), true)['invitations'])->toBe(1)
        ->and(Invitation::query()->whereKey($invitation->identifier())->exists())->toBeTrue();

    $counts = $action->prune(new SystemMutationContext('Retention cleanup', 'prune-test'));

    expect($counts['invitations'])->toBe(1)
        ->and($counts['passkeys'])->toBe(1)
        ->and(Invitation::query()->whereKey($invitation->identifier())->exists())->toBeFalse()
        ->and(Passkey::query()->whereKey($passkey->identifier())->exists())->toBeFalse()
        ->and(AuthAudit::query()->whereKey($audit->identifier())->exists())->toBeTrue();
});

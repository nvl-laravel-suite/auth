<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Auth\Services\PrincipalEmailIdentityAdoption;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\SystemMutationContext;

it('reports a ready fresh canonical email schema without adoption writes', function (): void {
    $user = $this->user();
    expect(app(PrincipalEmailIdentityAdoption::class)->plan())->toBe(['missing' => 0, 'collisions' => [], 'ready' => true]);
});

function retainedEmailSchema(): void
{
    $model = new TestUser;
    $model->getConnection()->getSchemaBuilder()->table($model->getTable(), function (Blueprint $table): void {
        $table->dropUnique(PrincipalEmailIdentity::INDEX);
        $table->dropColumn('email_identity_hash');
    });
    (require dirname(__DIR__, 2).'/database/migrations/2026_10_27_000003_nvl_auth_add_normalized_email_identity.php')->up();
}

function authorizeEmailAdoption(): void
{
    app()->instance(SystemMutationAccess::class, new class implements SystemMutationAccess
    {
        public function allows(SystemMutationContext $context, string $ability, mixed $target = null): bool
        {
            return $ability === 'nvl.auth.users.adoptEmailIdentities';
        }
    });
}

it('plans retained collisions without writes and refuses authorized apply', function (): void {
    $first = $this->user('Mixed@example.test');
    $second = $this->user('other@example.test');
    retainedEmailSchema();
    $second->getConnection()->table($second->getTable())->where('id', $second->id)->update(['email' => ' mixed@example.test']);
    authorizeEmailAdoption();
    $service = app(PrincipalEmailIdentityAdoption::class);
    $plan = $service->plan();
    expect($plan['missing'])->toBe(2)->and($plan['ready'])->toBeFalse()
        ->and($plan['collisions'][0]['subjectIds'])->toHaveCount(2)
        ->and(json_encode($plan))->not->toContain('Mixed@example.test');
    expect(fn () => $service->apply(new SystemMutationContext('Reviewed collision', 'test')))->toThrow(AuthException::class, 'collisions');
    expect($first->fresh()->getAttribute('email_identity_hash'))->toBeNull();
    expect(fn () => $this->user('new@example.test'))->toThrow(AuthException::class, 'adoption');
});

it('requires authority and preserves retained fields across separate backfill and schema finalization', function (bool $hostOwned): void {
    $user = $this->user('Mixed@example.test');
    $original = $user->getRawOriginal();
    retainedEmailSchema();
    config(['nvl-auth.migrations.enabled' => ! $hostOwned]);
    $context = new SystemMutationContext('Reviewed adoption; workers drained', 'test');
    app()->instance(SystemMutationAccess::class, new DenySystemMutationAccess);
    expect(fn () => app(PrincipalEmailIdentityAdoption::class)->apply($context))->toThrow(AuthException::class);
    authorizeEmailAdoption();
    $result = app(PrincipalEmailIdentityAdoption::class)->apply($context);
    expect($result)->toBe(['updated' => 1, 'finalized' => ! $hostOwned]);
    $fresh = $user->fresh();
    expect($fresh->email)->toBe($original['email'])
        ->and($fresh->getRawOriginal('password'))->toBe($original['password'])
        ->and($fresh->getAttribute('email_identity_hash'))->toBe(hash('sha256', 'mixed@example.test'));
    $definition = collect($fresh->getConnection()->getSchemaBuilder()->getColumns($fresh->getTable()))->firstWhere('name', 'email_identity_hash');
    expect($definition['nullable'])->toBe($hostOwned);
})->with([false, true]);

it('keeps the adoption command read only by default and requires an explicit apply reason', function (): void {
    $user = $this->user();
    retainedEmailSchema();
    $this->artisan('nvl:auth:adopt-email-identities')->assertSuccessful();
    expect($user->fresh()->getAttribute('email_identity_hash'))->toBeNull();
    expect(fn () => Artisan::call('nvl:auth:adopt-email-identities', ['--apply' => true]))->toThrow(InvalidArgumentException::class, 'reason');
    expect($user->fresh()->getAttribute('email_identity_hash'))->toBeNull();
});

it('reads only identity columns from retained principals while planning and applying adoption', function (): void {
    $this->user('first@example.test');
    $this->user('second@example.test');
    retainedEmailSchema();
    authorizeEmailAdoption();
    $model = new TestUser;
    $from = 'from '.$model->getConnection()->getQueryGrammar()->wrapTable($model->getTable());
    $reads = [];
    $model->getConnection()->listen(function (QueryExecuted $query) use (&$reads, $from): void {
        if (str_starts_with($query->sql, 'select') && str_contains($query->sql, $from)) {
            $reads[] = $query->sql;
        }
    });
    $service = app(PrincipalEmailIdentityAdoption::class);

    expect($service->plan()['missing'])->toBe(2)
        ->and($service->apply(new SystemMutationContext('Reviewed adoption; workers drained', 'projection'))['updated'])->toBe(2)
        ->and($reads)->not->toBeEmpty();
    foreach ($reads as $sql) {
        expect($sql)->not->toContain('select *')->not->toContain('password');
    }
});

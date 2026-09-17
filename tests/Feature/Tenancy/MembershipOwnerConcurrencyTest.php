<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Tests\Fixtures\AuthMembershipRace;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('serializes simultaneous owner removals and retains one active owner', function (): void {
    $driver = DB::connection()->getDriverName();
    if (! in_array($driver, ['pgsql', 'mysql'], true) || ! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The real owner race runs only in the PostgreSQL/MySQL/MariaDB matrix with pcntl.');
    }
    $scenario = new AuthTenancyScenario;
    $first = $this->user('race-first@example.test');
    $second = $this->user('race-second@example.test');
    $firstMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($first), true);
    $secondMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($second), true);
    $connection = config('database.default');
    if (! is_string($connection)) {
        throw new RuntimeException('The race connection is unavailable.');
    }

    $results = $scenario->run($scenario->a(), fn (): array => AuthMembershipRace::run($connection, [
        static fn (): array => ['id' => app(RevokeMembershipAction::class)->execute($first, $firstMembership->identifier(), 1)->identifier()],
        static fn (): array => ['id' => app(RevokeMembershipAction::class)->execute($second, $secondMembership->identifier(), 1)->identifier()],
    ]));

    expect(collect($results)->where('ok', true))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('code', 'membership_last_owner'))->toHaveCount(1)
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('status', MembershipStatus::Active->value)->where('is_owner', true)->count())->toBe(1);
});

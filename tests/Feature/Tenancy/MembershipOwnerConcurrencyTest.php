<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Tests\Fixtures\AuthMembershipRace;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\Tests\NativeOwnerConcurrencyTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;

uses(NativeOwnerConcurrencyTestCase::class);

it('serializes simultaneous owner removals and retains one active owner', function (): void {
    $driver = DB::connection()->getDriverName();
    if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true) || ! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The real owner race runs only in the PostgreSQL/MySQL/MariaDB matrix with pcntl.');
    }
    $scenario = new AuthOwnerScenario;
    $first = $this->user('race-first@example.test');
    $second = $this->user('race-second@example.test');
    $firstMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($first), true);
    $secondMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($second), true);
    $connection = config('database.default');
    if (! is_string($connection)) {
        throw new RuntimeException('The race connection is unavailable.');
    }

    $results = $scenario->run($scenario->a(), fn (): array => AuthMembershipRace::run($connection, [
        static fn (): array => ['id' => app(AuthMemberships::class)->revoke($first, $firstMembership->identifier(), 1)->identifier()],
        static fn (): array => ['id' => app(AuthMemberships::class)->revoke($second, $secondMembership->identifier(), 1)->identifier()],
    ]));

    expect(collect($results)->where('ok', true))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('code', 'membership_last_owner'))->toHaveCount(1)
        ->and(collect($results)->where('error', QueryException::class))->toHaveCount(0)
        ->and($scenario->run($scenario->a(), fn (): int => OwnerMembership::query()
            ->where('status', MembershipStatus::Active->value)->where('is_owner', true)->count()))->toBe(1);
});

it('serializes direct acceptance against registration without a database deadlock', function (): void {
    $driver = DB::connection()->getDriverName();
    if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true) || ! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The real invitation race runs only in the PostgreSQL/MySQL/MariaDB matrix with pcntl.');
    }
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('race-inviter@example.test');
    $recipient = $this->user('race-recipient@example.test');
    $recipient->markEmailAsVerified();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(AuthInvitations::class)->create(
        ['recipient' => $recipient->email],
        $owner,
    ));
    $registration = ['token' => $issued['token'], 'name' => 'Race Recipient', 'password' => 'correct-password', 'passwordConfirmation' => 'correct-password'];
    $connection = config('database.default');
    if (! is_string($connection)) {
        throw new RuntimeException('The race connection is unavailable.');
    }

    $results = AuthMembershipRace::run($connection, [
        static fn (): array => ['id' => app(AuthInvitations::class)->accept($issued['token'], $recipient)->identifier()],
        static fn (): array => ['id' => app(AuthInvitations::class)->register($registration, $recipient)['invitation']->identifier()],
    ]);

    expect(collect($results)->where('ok', true))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('code', 'invitation_invalid'))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('error', QueryException::class))->toHaveCount(0)
        ->and($scenario->run($scenario->a(), fn (): int => OwnerMembership::query()
            ->where('subject_id', $recipient->getAuthIdentifier())->count()))->toBe(1);
});

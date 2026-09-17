<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Tests\Fixtures\AuthMembershipRace;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('serializes simultaneous owner removals and retains one active owner', function (): void {
    $driver = DB::connection()->getDriverName();
    if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true) || ! function_exists('pcntl_fork')) {
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
        ->and(collect($results)->where('error', QueryException::class))->toHaveCount(0)
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('status', MembershipStatus::Active->value)->where('is_owner', true)->count())->toBe(1);
});

it('serializes direct acceptance against registration without a database deadlock', function (): void {
    $driver = DB::connection()->getDriverName();
    if (! in_array($driver, ['pgsql', 'mysql', 'mariadb'], true) || ! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The real invitation race runs only in the PostgreSQL/MySQL/MariaDB matrix with pcntl.');
    }
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('race-inviter@example.test');
    $recipient = $this->user('race-recipient@example.test');
    $recipient->markEmailAsVerified();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData($recipient->email),
        $owner,
    ));
    $registration = new AcceptInvitationData(
        token: $issued->token,
        name: 'Race Recipient',
        password: 'correct-password',
        passwordConfirmation: 'correct-password',
    );
    $connection = config('database.default');
    if (! is_string($connection)) {
        throw new RuntimeException('The race connection is unavailable.');
    }

    $results = AuthMembershipRace::run($connection, [
        static fn (): array => ['id' => app(AcceptInvitationAction::class)->execute($issued->token, $recipient)->identifier()],
        static fn (): array => ['id' => app(RegisterInvitationAction::class)->execute($registration, $recipient)->invitation->identifier()],
    ]);

    expect(collect($results)->where('ok', true))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('code', 'invitation_invalid'))->toHaveCount(1, json_encode($results, JSON_THROW_ON_ERROR))
        ->and(collect($results)->where('error', QueryException::class))->toHaveCount(0)
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('subject_id', $recipient->getAuthIdentifier())->count())->toBe(1);
});

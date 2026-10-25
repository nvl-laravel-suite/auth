<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Services\AuthCommittedAudit;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Tests\CommittedDeliveryTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;

uses(CommittedDeliveryTestCase::class);

it('emits verification data without sending and marks the host email verified', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    $user = $this->user();
    Event::fake([AuthDeliveryRequested::class]);
    $connection = $user->getConnection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();

    try {
        app(AuthEmailVerification::class)->request($user, 'en');
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }

    Event::assertDispatched(AuthDeliveryRequested::class, function (AuthDeliveryRequested $event) use ($user): bool {
        return $event->request->recipient === $user->email
            && $event->request->payload['subject_id'] === (string) $user->getKey();
    });

    expect(app(AuthEmailVerification::class)->verify($user))->toBeTrue()
        ->and($user->refresh()->hasVerifiedEmail())->toBeTrue()
        ->and(app(AuthEmailVerification::class)->verify($user))->toBeFalse();
});

it('uses laravel password broker storage and emits delivery instead of notifications', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();
    $connection = $user->getConnection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();
    try {
        app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    expect($event)->toBeInstanceOf(AuthDeliveryRequested::class)
        ->and($event->request->payload['token'])->toBeString();

    app(AuthPasswords::class)->reset(
        ['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'new-secure-password', 'passwordConfirmation' => 'new-secure-password']
    );

    expect(Hash::check('new-secure-password', $user->refresh()->password))->toBeTrue();
});

it('uses the original directly supplied invitation audit recorder after the owning commit', function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    $originalRecorder = new class implements AuthAuditRecorder
    {
        /** @var list<string> */
        public array $actions = [];

        /** @param array<string, mixed> $metadata */
        public function record(
            string $action,
            string $outcome = 'success',
            ?SubjectReference $subject = null,
            ?Authenticatable $actor = null,
            ?string $clientId = null,
            array $metadata = [],
        ): ?object {
            $this->actions[] = $action;

            return null;
        }
    };
    $adapterRecorder = clone $originalRecorder;
    $adapter = app(AuthCommittedAudit::class)->withRecorder($adapterRecorder);
    $action = app()->makeWith(AuthInvitations::class, ['audits' => $originalRecorder, 'committedAudits' => $adapter]);
    $connection = app('db')->connection();
    expect($connection->transactionLevel())->toBe(0);
    $connection->beginTransaction();

    try {
        $issued = $action->create(
            ['recipient' => 'direct-recorder@example.test'],
            authority: new SystemMutationContext('Explicit commit test', 'direct-recorder'),
        );
        expect($issued['invitation']->getConnection())->toBe($connection)
            ->and($originalRecorder->actions)->toBe([])
            ->and($adapterRecorder->actions)->toBe([]);
        Event::assertNotDispatched(AuthDeliveryRequested::class);
        $connection->commit();
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }

    expect($originalRecorder->actions)->toBe(['invitation.issued'])
        ->and($adapterRecorder->actions)->toBe([]);
    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
});

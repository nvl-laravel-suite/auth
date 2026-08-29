<?php

declare(strict_types=1);

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\FindActiveInvitationAction;
use Nvl\Auth\Actions\Invitations\ListInvitationProjectionsAction;
use Nvl\Auth\Actions\Invitations\ListInvitationsAction;
use Nvl\Auth\Actions\Invitations\RecordInvitationDeliveryOutcomeAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Invitations\ResendInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\InvitationAccepted;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\SubjectReference;

beforeEach(function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
});

it('issues consumes and audits a simple invitation without delivery persistence', function (): void {
    Event::fake([AuthDeliveryRequested::class, InvitationAccepted::class]);
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', [
        'member_id',
        'channel',
    ]);
    $actor = $this->user('actor@example.test');
    $consumer = $this->user('consumer@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'consumer@example.test',
            metadata: [
                'member_id' => 'member-1',
                'channel' => 'partner',
                'private_note' => 'not-for-delivery',
            ],
        ),
        $actor,
    );

    expect($issued->invitation)->toBeInstanceOf(Invitation::class)
        ->and($issued->token)->not->toBeEmpty()
        ->and($issued->invitation->getRawOriginal('token_hash'))->not->toBe($issued->token)
        ->and($issued->invitation->getRawOriginal('recipient'))->not->toBe('consumer@example.test');

    $accepted = app(AcceptInvitationAction::class)->execute($issued->token, $consumer);

    expect($accepted->accepted_at)->not->toBeNull()
        ->and($accepted->accepted_by_id)->toBe((string) $consumer->getKey())
        ->and(AuthAudit::query()->count())->toBe(2)
        ->and(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $consumer))
        ->toThrow(AuthException::class);
    Event::assertDispatched(AuthDeliveryRequested::class, static fn (AuthDeliveryRequested $event): bool => $event->request->feature === AuthFeature::Invitations
        && $event->request->payload['token'] === $issued->token
        && $event->request->invitation?->id === $issued->invitation->identifier()
        && $event->request->invitation->recipient === 'consumer@example.test'
        && $event->request->invitation->inviter?->id === (string) $actor->getKey()
        && $event->request->invitation->metadata === [
            'member_id' => 'member-1',
            'channel' => 'partner',
        ]
        && $event->request->invitation->resendCount === 0);
    Event::assertDispatchedTimes(InvitationAccepted::class, 1);
    Event::assertDispatched(
        InvitationAccepted::class,
        static fn (InvitationAccepted $event): bool => $event->invitationId === $issued->invitation->identifier()
            && $event->type === $issued->invitation->type
            && $event->purpose === $issued->invitation->purpose
            && $event->subject->identifier === (string) $consumer->getKey()
            && $event->acceptedAt?->equalTo($accepted->accepted_at) === true,
    );
    /** @var AuthDeliveryRequested $deliveryEvent */
    $deliveryEvent = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    /** @var InvitationAccepted $acceptanceEvent */
    $acceptanceEvent = Event::dispatched(InvitationAccepted::class)->sole()[0];
    /** @var InvitationAccepted $restoredAcceptanceEvent */
    $restoredAcceptanceEvent = unserialize(serialize($acceptanceEvent));
    $deliverySnapshot = json_encode(
        $deliveryEvent->request->invitation?->toArray(),
        JSON_THROW_ON_ERROR,
    );

    expect($restoredAcceptanceEvent->acceptedAt?->equalTo($accepted->accepted_at))->toBeTrue()
        ->and($deliverySnapshot)->not->toContain(
            $issued->token,
            'private_note',
            'not-for-delivery',
            'token_hash',
            'active_key',
            'recipient_hash',
        );
});

it('publishes current typed invitation context when resending', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    config()->set('nvl-auth.features.invitations.settings.resend_cooldown_seconds', 1);
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', ['member_id']);
    $actor = $this->user('resend.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'resend.invitee@example.test',
            metadata: ['member_id' => 'member-1'],
        ),
        $actor,
    );
    $issued->invitation->forceFill(['last_sent_at' => now()->subSeconds(2)])->save();

    $resent = app(ResendInvitationAction::class)->execute($issued->invitation, $actor);
    $events = Event::dispatched(AuthDeliveryRequested::class);
    /** @var AuthDeliveryRequested $event */
    $event = $events->last()[0];

    expect($resent->invitation->resend_count)->toBe(1)
        ->and($event->request->invitation?->id)->toBe($issued->invitation->identifier())
        ->and($event->request->invitation?->resendCount)->toBe(1)
        ->and($event->request->invitation?->metadata)->toBe(['member_id' => 'member-1']);
});

it('revokes invitations while the feature is disabled', function (): void {
    $actor = $this->user('actor@example.test');
    $issued = app(CreateInvitationAction::class)->execute(new StoreInvitationData('invitee@example.test'), $actor);
    config()->set('nvl-auth.features.invitations.enabled', false);

    $revoked = app(RevokeInvitationAction::class)->execute($issued->invitation, $actor);

    expect($revoked->revoked_at)->not->toBeNull()
        ->and(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $actor))
        ->toThrow(AuthException::class);
});

it('enforces one active invitation per recipient and purpose while preserving history', function (): void {
    $actor = $this->user('actor@example.test');
    $data = new StoreInvitationData('invitee@example.test');
    $first = app(CreateInvitationAction::class)->execute($data, $actor);

    expect(fn () => app(CreateInvitationAction::class)->execute($data, $actor))
        ->toThrow(AuthException::class, 'active invitation');

    $first->invitation->forceFill(['expires_at' => now()->subMinute()])->save();
    $replacement = app(CreateInvitationAction::class)->execute($data, $actor);

    expect($replacement->invitation->identifier())->not->toBe($first->invitation->identifier())
        ->and(Invitation::query()->count())->toBe(2);
});

it('provisions the package principal out of the box for public invitation acceptance', function (): void {
    Event::fake([InvitationAccepted::class]);
    $actor = $this->user('invitation.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('new.invitee@example.test'),
        $actor,
    );
    $registered = app(RegisterInvitationAction::class)->execute(new AcceptInvitationData(
        token: $issued->token,
        password: 'SecurePassword123',
        passwordConfirmation: 'SecurePassword123',
        name: 'New Invitee',
        locale: 'bg',
    ));
    $subject = $registered->subject;
    $accepted = $registered->invitation;

    expect($subject)->toBeInstanceOf(User::class)
        ->and($subject->email)->toBe('new.invitee@example.test')
        ->and($subject->locale)->toBe('bg')
        ->and($accepted->accepted_by_id)->toBe($subject->id);
    Event::assertDispatchedTimes(InvitationAccepted::class, 1);
    Event::assertDispatched(
        InvitationAccepted::class,
        static fn (InvitationAccepted $event): bool => $event->invitationId === $accepted->identifier()
            && $event->subject->identifier === $subject->id
            && $event->acceptedAt?->equalTo($accepted->accepted_at) === true,
    );
});

it('keeps invitation acceptance events privacy bounded', function (): void {
    $subject = $this->user('privacy.invitee@example.test');
    $event = new InvitationAccepted(
        invitationId: 'invitation-1',
        type: 'account',
        purpose: 'registration',
        subject: SubjectReference::fromAuthenticatable($subject),
    );
    $serialized = serialize($event);

    expect($event)->toBeInstanceOf(ShouldDispatchAfterCommit::class)
        ->and(get_object_vars($event))->toHaveKeys([
            'invitationId',
            'type',
            'purpose',
            'subject',
            'acceptedAt',
        ])->not->toHaveKeys([
            'token',
            'recipient',
            'metadata',
        ])
        ->and($event->acceptedAt)->toBeNull()
        ->and($serialized)->not->toContain('privacy.invitee@example.test');
});

it('rejects configured invitation delivery metadata that is not bounded scalar data', function (): void {
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', ['member_id']);
    $actor = $this->user('metadata.owner@example.test');

    expect(fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'metadata.invitee@example.test',
            metadata: ['member_id' => ['nested' => 'value']],
        ),
        $actor,
    ))->toThrow(AuthException::class, 'scalar');
});

it('rejects protected metadata keys and malformed stored grant projections', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', ['active_key']);
    $actor = $this->user('projection.owner@example.test');

    expect(fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'protected.invitee@example.test',
            metadata: ['active_key' => 'protected-value'],
        ),
        $actor,
    ))->toThrow(AuthException::class, 'safe allowlist');

    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', []);
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('malformed.invitee@example.test'),
        $actor,
    );
    $issued->invitation->forceFill([
        'roles' => ['named' => 'member'],
        'last_sent_at' => now()->subMinutes(2),
    ])->save();

    expect(fn () => app(ResendInvitationAction::class)->execute($issued->invitation, $actor))
        ->toThrow(AuthException::class, 'roles must be a distinct bounded list');
    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
});

it('supports explicitly authorized actorless issuance expiry and exact indexed filters', function (): void {
    $actor = $this->user('filter.owner@example.test');
    $expiresAt = now()->addHours(4)->startOfSecond()->toImmutable();
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'candidate@example.test',
            type: 'candidate',
            context: 'campaign-42',
        ),
        context: new InvitationIssuanceContext(
            actorlessAuthorized: true,
            expiresAt: $expiresAt,
            returnPath: '/candidate/welcome',
        ),
    );

    expect($issued->invitation->inviter_id)->toBeNull()
        ->and($issued->invitation->expires_at->equalTo($expiresAt))->toBeTrue()
        ->and($issued->invitation->metadata['return_path'])->toBe('/candidate/welcome')
        ->and(app(ListInvitationsAction::class)->execute($actor, new InvitationIndexQueryData(
            recipient: 'CANDIDATE@example.test',
            type: 'candidate',
            lifecycle: 'active',
            context: 'campaign-42',
        ))->total())->toBe(1)
        ->and(app(ListInvitationsAction::class)->execute($actor, new InvitationIndexQueryData(
            recipient: 'candidate@other.test',
        ))->total())->toBe(0);

    expect(fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('unauthorized@example.test'),
    ))->toThrow(AuthException::class, 'explicitly authorized');
});

it('lists bounded invitation projections with multi-type filters and constant query cost', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    config()->set('nvl-auth.features.invitations.settings.delivery_metadata_keys', ['member_id']);
    $actor = $this->user('projection-list.owner@example.test');

    foreach ([
        ['candidate.one@example.test', 'candidate', 'campaign-42'],
        ['registration.one@example.test', 'registration', 'campaign-42'],
        ['candidate.two@example.test', 'candidate', 'campaign-else'],
    ] as [$recipient, $type, $context]) {
        app(CreateInvitationAction::class)->execute(
            new StoreInvitationData(
                recipient: $recipient,
                type: $type,
                context: $context,
                metadata: [
                    'member_id' => "member-{$type}",
                    'private_note' => 'not-for-consumers',
                ],
            ),
            $actor,
        );
    }

    $page = app(ListInvitationProjectionsAction::class)->execute(
        $actor,
        new InvitationIndexQueryData(
            types: ['candidate', 'registration', 'candidate'],
            lifecycle: 'active',
            context: 'campaign-42',
        ),
        100,
    );
    $snapshot = json_encode($page->items(), JSON_THROW_ON_ERROR);

    expect($page->items())->toHaveCount(2)
        ->each->toBeInstanceOf(InvitationReadData::class)
        ->and($snapshot)->not->toContain(
            'token_hash',
            'active_key',
            'recipient_hash',
            'context_hash',
            'current_delivery_message_id',
            'private_note',
            'not-for-consumers',
        );

    Invitation::factory()->count(100)->create();
    DB::flushQueryLog();
    DB::enableQueryLog();
    app(ListInvitationProjectionsAction::class)->execute($actor, perPage: 100)->items();
    $queryCount = count(DB::getQueryLog());
    DB::disableQueryLog();

    expect($queryCount)->toBeLessThanOrEqual(2);
});

it('finds active invitations through an explicit trusted lookup boundary', function (): void {
    $actor = $this->user('active-lookup.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(
            recipient: 'Candidate@Example.Test',
            type: 'candidate',
            purpose: 'registration',
            context: 'campaign-42',
        ),
        $actor,
    );
    $lookup = app(FindActiveInvitationAction::class);

    expect(fn () => $lookup->execute('candidate@example.test', 'registration'))
        ->toThrow(AuthException::class, 'explicitly authorized')
        ->and($lookup->execute(
            recipient: ' CANDIDATE@example.test ',
            purpose: 'registration',
            types: ['candidate'],
            context: 'campaign-42',
            issuance: new InvitationIssuanceContext(actorlessAuthorized: true),
        )?->id)->toBe($issued->invitation->identifier())
        ->and($lookup->execute(
            recipient: 'missing@example.test',
            purpose: 'registration',
            types: ['candidate'],
            context: 'campaign-42',
            issuance: new InvitationIssuanceContext(actorlessAuthorized: true),
        ))->toBeNull();

    $issued->invitation->forceFill(['expires_at' => now()->subMinute()])->save();

    expect($lookup->execute(
        recipient: 'candidate@example.test',
        purpose: 'registration',
        actor: $actor,
    ))->toBeNull();
});

it('supports ID lifecycle mutations and records current delivery outcomes idempotently', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    config()->set('nvl-auth.features.invitations.settings.resend_cooldown_seconds', 1);
    $actor = $this->user('outcome.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('outcome.invitee@example.test'),
        $actor,
    );
    /** @var AuthDeliveryRequested $createdEvent */
    $createdEvent = Event::dispatched(AuthDeliveryRequested::class)->sole()[0];
    $initialMessageId = $createdEvent->request->messageId;
    $invitation = $issued->invitation->refresh();
    $modelSnapshot = json_encode($invitation, JSON_THROW_ON_ERROR);

    expect($invitation->current_delivery_message_id)->toBe($initialMessageId)
        ->and($invitation->delivery_status)->toBe(InvitationDeliveryStatus::Pending)
        ->and($invitation->delivery_attempted_at)->toBeNull()
        ->and($modelSnapshot)->not->toContain(
            'current_delivery_message_id',
            $initialMessageId,
        );

    $invitation->forceFill(['last_sent_at' => now()->subSeconds(2)])->save();
    $resent = app(ResendInvitationAction::class)->execute($invitation->identifier(), $actor);
    /** @var AuthDeliveryRequested $resentEvent */
    $resentEvent = Event::dispatched(AuthDeliveryRequested::class)->last()[0];
    $currentMessageId = $resentEvent->request->messageId;
    $outcomes = app(RecordInvitationDeliveryOutcomeAction::class);
    $occurredAt = now()->startOfSecond()->toImmutable();

    $outcomes->execute(
        $resent->invitation->identifier(),
        $initialMessageId,
        InvitationDeliveryStatus::Failed,
        $occurredAt,
        'transport_failed',
    );

    expect($resent->invitation->refresh()->delivery_status)->toBe(InvitationDeliveryStatus::Pending)
        ->and(AuthAudit::query()->where('action', 'invitation.delivery_outcome_stale')->count())->toBe(1);

    $outcomes->execute(
        $resent->invitation->identifier(),
        $currentMessageId,
        InvitationDeliveryStatus::Failed,
        $occurredAt,
        'transport_failed',
    );
    $outcomes->execute(
        $resent->invitation->identifier(),
        $currentMessageId,
        InvitationDeliveryStatus::Failed,
        $occurredAt->addMinute(),
        'different_failure',
    );
    $failed = $resent->invitation->refresh();

    expect($failed->delivery_status)->toBe(InvitationDeliveryStatus::Failed)
        ->and($failed->delivery_failed_at?->equalTo($occurredAt))->toBeTrue()
        ->and($failed->delivery_failure_code)->toBe('transport_failed');

    $deliveredAt = $occurredAt->addMinutes(2);
    $outcomes->execute(
        $failed->identifier(),
        $currentMessageId,
        InvitationDeliveryStatus::Delivered,
        $deliveredAt,
    );
    $delivered = $failed->refresh();

    expect($delivered->delivery_status)->toBe(InvitationDeliveryStatus::Delivered)
        ->and($delivered->delivered_at?->equalTo($deliveredAt))->toBeTrue()
        ->and($delivered->delivery_failed_at)->toBeNull()
        ->and($delivered->delivery_failure_code)->toBeNull()
        ->and(app(RevokeInvitationAction::class)->execute($delivered->identifier(), $actor)->revoked_at)->not->toBeNull();
});

it('rejects invalid invitation delivery outcome contracts', function (): void {
    $actor = $this->user('outcome-validation.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('outcome-validation.invitee@example.test'),
        $actor,
    );
    $messageId = $issued->invitation->refresh()->current_delivery_message_id;
    $outcomes = app(RecordInvitationDeliveryOutcomeAction::class);
    $occurredAt = now()->toImmutable();

    expect(fn () => $outcomes->execute(
        $issued->invitation->identifier(),
        (string) $messageId,
        InvitationDeliveryStatus::Pending,
        $occurredAt,
    ))->toThrow(InvalidArgumentException::class, 'Delivered or Failed')
        ->and(fn () => $outcomes->execute(
            $issued->invitation->identifier(),
            (string) $messageId,
            InvitationDeliveryStatus::Failed,
            $occurredAt,
        ))->toThrow(InvalidArgumentException::class, 'failure code')
        ->and(fn () => $outcomes->execute(
            $issued->invitation->identifier(),
            (string) $messageId,
            InvitationDeliveryStatus::Delivered,
            $occurredAt,
            'not_allowed',
        ))->toThrow(InvalidArgumentException::class, 'only')
        ->and(fn () => $outcomes->execute(
            $issued->invitation->identifier(),
            (string) $messageId,
            InvitationDeliveryStatus::Failed,
            $occurredAt,
            'Unsafe failure code',
        ))->toThrow(InvalidArgumentException::class, 'failure code');
});

it('publishes invitation delivery only after pending state and its audit are committed', function (): void {
    $actor = $this->user('delivery-order.owner@example.test');
    $connectionName = 'auth_delivery_order';
    $originalConnection = config('nvl-auth.connection');
    config()->set("database.connections.{$connectionName}", [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    config()->set('nvl-auth.connection', $connectionName);
    DB::purge($connectionName);

    foreach ([
        '2026_08_02_000000_create_nvl_auth_tables.php',
        '2026_08_12_000000_add_auth_delivery_context_columns.php',
        '2026_08_28_000000_add_invitation_delivery_outcomes.php',
    ] as $migrationFile) {
        $migration = require dirname(__DIR__, 2)."/database/migrations/{$migrationFile}";
        $migration->up();
    }

    $observed = [];
    Event::listen(
        AuthDeliveryRequested::class,
        static function (AuthDeliveryRequested $event) use (&$observed, $connectionName): void {
            $invitation = Invitation::query()->find($event->request->invitation?->id);

            $observed[] = [
                'transaction_level' => DB::connection($connectionName)->transactionLevel(),
                'message_id' => $invitation?->current_delivery_message_id,
                'delivery_status' => $invitation?->delivery_status,
                'audit_exists' => AuthAudit::query()
                    ->where('action', 'invitation.issued')
                    ->exists(),
            ];
        },
    );

    try {
        $issued = app(CreateInvitationAction::class)->execute(
            new StoreInvitationData('delivery-order.invitee@example.test'),
            $actor,
        );

        expect($observed)->toBe([[
            'transaction_level' => 0,
            'message_id' => $issued->invitation->current_delivery_message_id,
            'delivery_status' => InvitationDeliveryStatus::Pending,
            'audit_exists' => true,
        ]]);
    } finally {
        config()->set('nvl-auth.connection', $originalConnection);
        DB::purge($connectionName);
        config()->set("database.connections.{$connectionName}", null);
    }
});

it('rolls principal creation back when an invitation acceptance hook rejects', function (): void {
    Event::fake([InvitationAccepted::class]);
    $actor = $this->user('rollback.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('rollback.invitee@example.test'),
        $actor,
    );
    config()->set('nvl-auth.pipelines.invitation_accepted', [RejectLoginStage::class]);

    expect(fn () => app(RegisterInvitationAction::class)->execute(new AcceptInvitationData(
        token: $issued->token,
        password: 'SecurePassword123',
        passwordConfirmation: 'SecurePassword123',
        name: 'Rollback Invitee',
    )))->toThrow(AuthException::class, 'rejected');

    expect(User::query()->where('email', 'rollback.invitee@example.test')->exists())->toBeFalse()
        ->and($issued->invitation->refresh()->accepted_at)->toBeNull();
    Event::assertNotDispatched(InvitationAccepted::class);
});

it('supports a host-mapped social registration variant inside the invitation transaction', function (): void {
    $actor = $this->user('social.owner@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('social.invitee@example.test'),
        $actor,
    );
    $this->app->instance(InvitationRegistrationMapper::class, new class implements InvitationRegistrationMapper
    {
        public function map(Invitation $invitation, array $validated): array
        {
            return [
                'name' => $validated['name'],
                'email' => $invitation->recipient,
                'is_active' => true,
                'locale' => 'en',
                'timezone' => 'UTC',
                'profile' => $validated['extensions'],
            ];
        }
    });

    $registered = app(RegisterInvitationAction::class)->execute(new AcceptInvitationData(
        token: $issued->token,
        name: 'Social Invitee',
        registrationMethod: 'social',
        extensions: ['provider' => 'github', 'provider_user_id' => 'github-123'],
    ));

    expect($registered->subject)->toBeInstanceOf(User::class)
        ->and($registered->subject->profile)->toBe([
            'provider' => 'github',
            'provider_user_id' => 'github-123',
        ])
        ->and($registered->invitation->accepted_at)->not->toBeNull();
});

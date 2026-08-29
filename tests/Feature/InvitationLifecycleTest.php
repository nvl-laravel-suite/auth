<?php

declare(strict_types=1);

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\ListInvitationsAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Invitations\ResendInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
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

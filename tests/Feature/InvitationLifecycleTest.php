<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\ListInvitationsAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Queries\InvitationIndexQueryData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

beforeEach(function (): void {
    config()->set('nvl-auth.features.invitations.enabled', true);
});

it('issues consumes and audits a simple invitation without delivery persistence', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $actor = $this->user('actor@example.test');
    $consumer = $this->user('consumer@example.test');
    $issued = app(CreateInvitationAction::class)->execute(
        new StoreInvitationData('consumer@example.test'),
        $actor,
    );

    expect($issued->invitation)->toBeInstanceOf(Invitation::class)
        ->and($issued->token)->not->toBeEmpty()
        ->and($issued->invitation->getRawOriginal('token_hash'))->not->toBe($issued->token)
        ->and($issued->invitation->getRawOriginal('recipient'))->not->toBe('consumer@example.test');

    $accepted = app(AcceptInvitationAction::class)->execute($issued->token, $consumer);

    expect($accepted->accepted_at)->not->toBeNull()
        ->and($accepted->accepted_by_id)->toBe((string) $consumer->getKey())
        ->and(AuthAudit::query()->count())->toBe(2);
    Event::assertDispatched(AuthDeliveryRequested::class, static fn (AuthDeliveryRequested $event): bool => $event->request->feature === AuthFeature::Invitations
        && $event->request->payload['token'] === $issued->token);
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

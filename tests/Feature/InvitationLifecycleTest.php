<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;

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
    $subject = app(InvitationSubjectResolver::class)->resolve($issued->invitation, [
        'name' => 'New Invitee',
        'password' => 'SecurePassword123',
        'locale' => 'bg',
    ]);
    $accepted = app(AcceptInvitationAction::class)->execute($issued->token, $subject);

    expect($subject)->toBeInstanceOf(User::class)
        ->and($subject->email)->toBe('new.invitee@example.test')
        ->and($subject->locale)->toBe('bg')
        ->and($accepted->accepted_by_id)->toBe($subject->id);
});

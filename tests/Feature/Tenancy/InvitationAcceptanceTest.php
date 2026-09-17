<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('does not attach an invitation to a different authenticated identity', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $owner->markEmailAsVerified();
    $wrong = $this->user('wrong@example.test');
    $wrong->markEmailAsVerified();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));

    expect(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $wrong))
        ->toThrow(AuthException::class)
        ->and($issued->invitation->fresh()->accepted_at)->toBeNull();
});

it('issues independently per tenant and atomically enrolls the verified recipient', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $owner->markEmailAsVerified();
    $recipient = $this->user('invited@example.test');
    $recipient->markEmailAsVerified();
    $reference = SubjectReference::fromAuthenticatable($owner);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);

    $a = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));
    $b = $scenario->run($scenario->b(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));

    $accepted = app(AcceptInvitationAction::class)->execute($a->token, $recipient);

    expect($a->invitation->tenant_id)->toBe($scenario->a()->value)
        ->and($b->invitation->tenant_id)->toBe($scenario->b()->value)
        ->and($accepted->accepted_at)->not->toBeNull()
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeTrue()
        ->and(TenantMembership::query()->where('tenant_id', $scenario->b()->value)
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeFalse();
});

it('rolls back acceptance when the stored inviter is no longer an active member', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $recipient = $this->user('invited@example.test');
    $recipient->markEmailAsVerified();
    $membership = $scenario->member(
        $scenario->a(),
        SubjectReference::fromAuthenticatable($owner),
        true,
    );
    $issued = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));
    $membership->forceFill(['status' => MembershipStatus::Suspended])->save();

    expect(fn () => app(AcceptInvitationAction::class)->execute($issued->token, $recipient))
        ->toThrow(AuthException::class)
        ->and($issued->invitation->fresh()->accepted_at)->toBeNull()
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeFalse();
});

<?php

declare(strict_types=1);

use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\Services\AuthMemberships;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Services\OwnerIdentityResolver;

it('removes one membership without removing the other tenant or global account', function (): void {
    $scenario = new AuthOwnerScenario;
    $actor = $this->user('actor@example.test');
    $member = $this->user('member@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);
    $membershipA = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($member), true);

    $scenario->run($scenario->a(), fn () => app(AuthMemberships::class)->revoke($actor, $membershipA, 1));

    expect(fn () => app(AuthOwnerAccess::class)->assertCanEnter($member, app(OwnerIdentityResolver::class)->resolve($scenario->a())))
        ->toThrow(AuthException::class);
    app(AuthOwnerAccess::class)->assertCanEnter($member, app(OwnerIdentityResolver::class)->resolve($scenario->b()));
    expect($member->fresh())->not->toBeNull();
});

it('reactivates without restoring prior access and transfers ownership atomically', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('transfer-owner@example.test');
    $recipient = $this->user('transfer-recipient@example.test');
    $ownerMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $recipientMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($recipient));

    $scenario->run($scenario->a(), function () use ($owner, $ownerMembership, $recipientMembership): void {
        app(AuthMemberships::class)->transfer(
            $owner,
            $ownerMembership,
            $recipientMembership->identifier(), 1,
        );
    });

    expect($scenario->run($scenario->a(), fn () => $ownerMembership->fresh())->is_owner)->toBeFalse()
        ->and($scenario->run($scenario->a(), fn () => $recipientMembership->fresh())->is_owner)->toBeTrue();
});

it('lists only the authenticated principal own active memberships', function (): void {
    $scenario = new AuthOwnerScenario;
    $member = $this->user('own@example.test');
    $other = $this->user('other@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($other));

    $memberships = app(AuthMemberships::class)->own($member);

    expect($memberships)->toHaveCount(2)
        ->and($memberships->pluck('owner.key')->sort()->values()->all())->toBe(['7', '8']);
});

it('rejects stale revisions and removal of the sole owner', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner@example.test');
    $membership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);

    $scenario->run($scenario->a(), function () use ($membership, $owner): void {
        expect(fn () => app(AuthMemberships::class)->setStatus(
            $owner,
            $membership,
            MembershipStatus::Suspended, 7,
        ))->toThrow(AuthException::class, 'revision');

        expect(fn () => app(AuthMemberships::class)->revoke($owner, $membership, 1))
            ->toThrow(AuthException::class, 'owner');
    });
});

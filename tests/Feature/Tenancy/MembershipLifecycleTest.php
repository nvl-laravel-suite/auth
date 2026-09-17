<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Memberships\ListOwnMembershipsAction;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Actions\Memberships\SetMembershipStatusAction;
use Nvl\Auth\Actions\Memberships\TransferMembershipOwnershipAction;
use Nvl\Auth\Data\Mutations\TransferMembershipOwnershipData;
use Nvl\Auth\Data\Mutations\UpdateMembershipStatusData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;

it('removes one membership without removing the other tenant or global account', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('actor@example.test');
    $member = $this->user('member@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);
    $membershipA = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($member), true);

    $scenario->run($scenario->a(), fn () => app(RevokeMembershipAction::class)->execute($actor, $membershipA, 1));

    expect(fn () => app(TenantMembershipAccess::class)->assertMember($member, $scenario->a()))
        ->toThrow(AuthException::class);
    app(TenantMembershipAccess::class)->assertMember($member, $scenario->b());
    expect($member->fresh())->not->toBeNull();
});

it('reactivates without restoring prior access and transfers ownership atomically', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('transfer-owner@example.test');
    $recipient = $this->user('transfer-recipient@example.test');
    $ownerMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $recipientMembership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($recipient));

    $scenario->run($scenario->a(), function () use ($owner, $ownerMembership, $recipientMembership): void {
        app(TransferMembershipOwnershipAction::class)->execute(
            $owner,
            $ownerMembership,
            new TransferMembershipOwnershipData($recipientMembership->identifier(), 1),
        );
    });

    expect($ownerMembership->fresh()->is_owner)->toBeFalse()
        ->and($recipientMembership->fresh()->is_owner)->toBeTrue();
});

it('lists only the authenticated principal own active memberships', function (): void {
    $scenario = new AuthTenancyScenario;
    $member = $this->user('own@example.test');
    $other = $this->user('other@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->b(), SubjectReference::fromAuthenticatable($member));
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($other));

    $memberships = app(ListOwnMembershipsAction::class)->execute($member);

    expect($memberships)->toHaveCount(2)
        ->and($memberships->pluck('tenant_id')->all())->toBe([$scenario->a()->value, $scenario->b()->value]);
});

it('rejects stale revisions and removal of the sole owner', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $membership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);

    $scenario->run($scenario->a(), function () use ($membership, $owner): void {
        expect(fn () => app(SetMembershipStatusAction::class)->execute(
            $owner,
            $membership,
            new UpdateMembershipStatusData(MembershipStatus::Suspended, 7),
        ))->toThrow(AuthException::class, 'revision');

        expect(fn () => app(RevokeMembershipAction::class)->execute($owner, $membership, 1))
            ->toThrow(AuthException::class, 'owner');
    });
});

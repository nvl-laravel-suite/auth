<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('rolls back acceptance when the stored inviter is no longer an active member', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner@example.test');
    $recipient = $this->user('invited@example.test');
    $recipient->markEmailAsVerified();
    $membership = $scenario->member(
        $scenario->a(),
        SubjectReference::fromAuthenticatable($owner),
        true,
    );
    $issued = $scenario->run($scenario->a(), fn () => app(AuthInvitations::class)->create(
        ['recipient' => 'invited@example.test'],
        $owner,
    ));
    $scenario->run($scenario->a(), fn () => $membership->forceFill(['status' => MembershipStatus::Suspended])->save());

    expect(fn () => app(AuthInvitations::class)->accept($issued['token'], $recipient))
        ->toThrow(AuthException::class)
        ->and($scenario->run($scenario->a(), fn () => $issued['invitation']->fresh())->accepted_at)->toBeNull()
        ->and(DB::table('nvl_auth_owner_memberships')->where('owner_scope_key', $scenario->a()->scopeKey())
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeFalse();
});

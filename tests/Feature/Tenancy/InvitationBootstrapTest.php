<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Data\Mutations\AcceptInvitationData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\InvitationTenantBootstrap;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('discovers only the tenant recorded by a usable token', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));

    expect(app(InvitationTenantBootstrap::class)->tenantForToken($issued->token)?->value)
        ->toBe($scenario->a()->value)
        ->and(app(InvitationTenantBootstrap::class)->tenantForToken('wrong-token'))->toBeNull();

    $issued->invitation->forceFill(['revoked_at' => now()])->save();

    expect(app(InvitationTenantBootstrap::class)->tenantForToken($issued->token))->toBeNull();
});

it('requires authenticated proof before reusing an existing global identity', function (): void {
    $scenario = new AuthTenancyScenario;
    $owner = $this->user('owner@example.test');
    $recipient = $this->user('invited@example.test');
    $recipient->markEmailAsVerified();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateInvitationAction::class)->execute(
        new StoreInvitationData(recipient: 'invited@example.test'),
        $owner,
    ));
    $data = new AcceptInvitationData(
        token: $issued->token,
        name: 'Ignored Name',
        password: 'correct-password',
        passwordConfirmation: 'correct-password',
    );

    expect(fn () => app(RegisterInvitationAction::class)->execute($data))
        ->toThrow(AuthException::class);

    $result = app(RegisterInvitationAction::class)->execute($data, $recipient);

    expect($result->subject->getAuthIdentifier())->toBe($recipient->getAuthIdentifier())
        ->and(TenantMembership::query()->where('tenant_id', $scenario->a()->value)
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeTrue();
});

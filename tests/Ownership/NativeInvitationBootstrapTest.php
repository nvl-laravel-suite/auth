<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

it('discovers only the tenant recorded by a usable token', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(AuthInvitations::class)->create(
        ['recipient' => 'invited@example.test'],
        $owner,
    ));

    expect(OwnerReference::fromJson(app(AuthInvitations::class)->preview($issued['token'])->owner_reference)->scopeKey())
        ->toBe($scenario->a()->scopeKey())
        ->and(fn () => app(AuthInvitations::class)->preview('wrong-token'))->toThrow(AuthException::class);

    $scenario->run($scenario->a(), fn () => $issued['invitation']->forceFill(['revoked_at' => now()])->save());

    expect(fn () => app(AuthInvitations::class)->preview($issued['token']))->toThrow(AuthException::class);
});

it('requires authenticated proof before reusing an existing global identity', function (): void {
    $scenario = new AuthOwnerScenario;
    $owner = $this->user('owner@example.test');
    $recipient = $this->user('invited@example.test');
    $recipient->markEmailAsVerified();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($owner), true);
    $issued = $scenario->run($scenario->a(), fn () => app(AuthInvitations::class)->create(
        ['recipient' => 'invited@example.test'],
        $owner,
    ));
    $data = ['token' => $issued['token'], 'name' => 'Ignored Name', 'password' => 'correct-password', 'passwordConfirmation' => 'correct-password'];

    expect(fn () => app(AuthInvitations::class)->register($data))
        ->toThrow(AuthException::class);

    $result = app(AuthInvitations::class)->register($data, $recipient);

    expect($result['subject']->getAuthIdentifier())->toBe($recipient->getAuthIdentifier())
        ->and(DB::table('nvl_auth_owner_memberships')->where('owner_scope_key', $scenario->a()->scopeKey())
            ->where('subject_id', $recipient->getAuthIdentifier())->exists())->toBeTrue();
});

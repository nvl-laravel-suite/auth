<?php

declare(strict_types=1);

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\InvitationPrincipalResolver;
use Nvl\Auth\Services\PrincipalEmailIdentity;

it('reserves one normalized email identity including soft deleted principals', function (): void {
    $user = $this->user('Mixed@Example.test');
    $user->delete();
    expect(fn () => $this->user('  MIXED@example.test  '))->toThrow(UniqueConstraintViolationException::class);
});

it('derives protected hidden keys from the final factory email and resolves equivalents', function (): void {
    $user = $this->user('Mixed@Example.test');
    $key = hash('sha256', 'mixed@example.test');
    expect($user->getAttribute('email_identity_hash'))->toBe($key)
        ->and($user->getFillable())->not->toContain('email_identity_hash')
        ->and($user->toArray())->not->toHaveKey('email_identity_hash')
        ->and(app(AuthIdentifierResolver::class)->resolve('email', ' MIXED@example.test ')?->getAuthIdentifier())->toBe($user->getKey());
    $user->forceFill(['email_identity_hash' => str_repeat('0', 64)])->save();
    expect($user->fresh()->getAttribute('email_identity_hash'))->toBe($key);
    expect(app(PrincipalEmailIdentity::class)->normalize(' A+B.C@Example.TEST '))->toBe('a+b.c@example.test');
});

it('shares canonical email criteria across password proof broker reset and invitation reuse', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user('Mixed@Example.test');
    $proof = app(Authentication::class)->proveCredentials(['identifier' => ' MIXED@example.test ', 'password' => 'correct-password'], $this->authenticationContext());
    expect($proof->reveal())->not->toBeEmpty();
    app(AuthPasswords::class)->requestReset(['identifier' => ' MIXED@example.test ']);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    app(AuthPasswords::class)->reset(['identifier' => ' mixed@example.test ', 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    expect(password_verify('replacement-password', $user->fresh()->getAuthPassword()))->toBeTrue();
    $invitation = Invitation::factory()->create(['recipient' => ' mixed@example.test ']);
    expect(fn () => $user->getConnection()->transaction(fn () => app(InvitationPrincipalResolver::class)->resolve($invitation, [], null)))
        ->toThrow(AuthException::class, 'recipient identity');
    expect(User::query()->count())->toBe(1);
});

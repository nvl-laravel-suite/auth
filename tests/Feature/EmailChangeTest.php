<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthEmailChanges;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

it('keeps the old verified email until the new destination is proved once', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    $user = $this->user();
    $user->markEmailAsVerified();
    $context = $this->authenticationContext();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange)->reveal();
    Event::fake([AuthDeliveryRequested::class]);
    $service = app(AuthEmailChanges::class);
    $pending = $service->request($user, ' NEXT@example.test ', $grant, $context);
    expect($user->refresh()->email)->toBe('user@example.test')->and($user->hasVerifiedEmail())->toBeTrue();
    $delivery = Event::dispatched(AuthDeliveryRequested::class)->first(fn ($args) => $args[0]->request->type === AuthMessageType::EmailChangeVerification)[0]->request;
    $completed = $service->complete($user, $delivery->payload['token'], $context);
    expect($completed->email)->toBe('next@example.test')->and($completed->hasVerifiedEmail())->toBeTrue()->and(auth()->check())->toBeFalse();
    expect(fn () => $service->complete($user, $delivery->payload['token'], $context))->toThrow(AuthException::class);
    expect($pending->toArray())->not->toHaveKeys(['new_email', 'token_hash', 'email_hash', 'context']);
});

it('fails neutrally on completion conflict and keeps pending state on outer rollback', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    $user = $this->user();
    $other = $this->user('occupied@example.test');
    $context = $this->authenticationContext();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange)->reveal();
    Event::fake([AuthDeliveryRequested::class]);
    $service = app(AuthEmailChanges::class);
    $pending = $service->request($user, $other->email, $grant, $context);
    $token = Event::dispatched(AuthDeliveryRequested::class)->first(fn ($args) => $args[0]->request->type === AuthMessageType::EmailChangeVerification)[0]->request->payload['token'];
    expect(fn () => $service->complete($user, $token, $context))->toThrow(AuthException::class);
    expect($user->refresh()->email)->toBe('user@example.test')->and($pending->refresh()->consumed_at)->toBeNull();
    $other->update(['email' => 'released@example.test']);
    Event::fake([AuthDeliveryRequested::class]);
    expect(fn () => $user->getConnection()->transaction(function () use ($service, $user, $token, $context): void {
        $service->complete($user, $token, $context);
        throw new RuntimeException('rollback');
    }))->toThrow(RuntimeException::class, 'rollback');
    expect($user->refresh()->email)->toBe('user@example.test')->and($pending->refresh()->consumed_at)->toBeNull();
    Event::assertNotDispatched(AuthDeliveryRequested::class);
});

it('rejects immediate profile replacement and binds pending proof to the current browser revision', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    expect(fn () => app(AuthUsers::class)->updateProfile($user, ['email' => 'shortcut@example.test']))->toThrow(AuthException::class, 'AuthEmailChanges');
    Event::fake([AuthDeliveryRequested::class]);
    $service = app(AuthEmailChanges::class);
    $service->request($user, 'pending@example.test', $this->recentGrant($user, RecentAuthenticationPurpose::EmailChange)->reveal(), $context);
    $token = Event::dispatched(AuthDeliveryRequested::class)->first(fn ($args) => $args[0]->request->type === AuthMessageType::EmailChangeVerification)[0]->request->payload['token'];
    expect(fn () => $service->complete($user, $token, new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'another-browser')))->toThrow(AuthException::class);
    $user->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'security_containment'));
    expect(fn () => $service->complete($user, $token, $context))->toThrow(AuthException::class);
    expect($user->refresh()->email)->toBe('user@example.test');
});

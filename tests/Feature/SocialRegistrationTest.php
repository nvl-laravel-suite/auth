<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\ExternalIdentity;

beforeEach(function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open', 'nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.google' => []]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('google', 'new-subject', email: 'new@example.test', emailVerified: true, emailVerificationSource: 'test'))));
});

it('creates one social only principal from verified continuation and never authenticates it', function (): void {
    $context = $this->authenticationContext();
    $auth = app(AuthSocialAuthentication::class);
    $start = $auth->beginLogin('google', $context);
    $continuation = $auth->completeLogin('google', $start['intent']->reveal(), $context)['continuation']->reveal();
    $user = app(AuthRegistration::class)->registerSocial($continuation, ['name' => 'Social User'], $context);
    expect($user->getAuthPassword())->toBeNull()->and($user->email)->toBe('new@example.test')->and($user->hasVerifiedEmail())->toBeTrue()->and(auth()->check())->toBeFalse()
        ->and(SocialIdentity::query()->where('subject_id', $user->getKey())->count())->toBe(1);
    expect(fn () => app(AuthRegistration::class)->registerSocial($continuation, ['name' => 'Replay'], $context))->toThrow(AuthException::class);
    expect(User::query()->count())->toBe(1);
});

it('does not turn a matching email into account merging or orphan provisioning', function (): void {
    $this->user('new@example.test');
    $context = $this->authenticationContext();
    $auth = app(AuthSocialAuthentication::class);
    $start = $auth->beginLogin('google', $context);
    $continuation = $auth->completeLogin('google', $start['intent']->reveal(), $context)['continuation']->reveal();
    expect(fn () => app(AuthRegistration::class)->registerSocial($continuation, ['name' => 'Conflict'], $context))->toThrow(AuthException::class);
    expect(User::query()->count())->toBe(1)->and(SocialIdentity::query()->count())->toBe(0);
});

it('verifies a separate onboarding mailbox without fabricating provider provenance', function (): void {
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('google', 'without-email'))));
    $context = $this->authenticationContext();
    $auth = app(AuthSocialAuthentication::class);
    $signup = app(AuthRegistration::class);
    $start = $auth->beginLogin('google', $context);
    $secret = $auth->completeLogin('google', $start['intent']->reveal(), $context)['continuation']->reveal();
    expect(fn () => $signup->registerSocial($secret, ['name' => 'Local Mailbox'], $context))->toThrow(AuthException::class);
    Event::fake([AuthDeliveryRequested::class]);
    $signup->requestSocialEmailVerification($secret, 'local@example.test', $context);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $code = $event->request->payload['code'];
    expect(fn () => $signup->verifySocialEmail($secret, 'wrong', $context))->toThrow(AuthException::class);
    $replacement = $signup->verifySocialEmail($secret, $code, $context)->reveal();
    expect(fn () => $signup->registerSocial($secret, ['name' => 'Old receipt'], $context))->toThrow(AuthException::class);
    $user = $signup->registerSocial($replacement, ['name' => 'Local Mailbox'], $context);
    expect($user->email)->toBe('local@example.test')->and($user->hasVerifiedEmail())->toBeTrue()->and(SocialIdentity::query()->first()->profile['email_verified'])->toBeFalse();
});

it('admits invitation only social signup using the actual invitation and proved recipient', function (): void {
    config(['nvl-auth.features.registration.settings.mode' => 'invitation_only', 'nvl-auth.features.invitations.enabled' => true]);
    $invites = app(AuthInvitations::class);
    $invitation = $invites->create(['recipient' => 'new@example.test'], $this->user('inviter@example.test'));
    $context = $this->authenticationContext();
    $auth = app(AuthSocialAuthentication::class);
    $start = $auth->beginLogin('google', $context);
    $secret = $auth->completeLogin('google', $start['intent']->reveal(), $context)['continuation']->reveal();
    expect(fn () => app(AuthRegistration::class)->registerSocial($secret, ['name' => 'No invitation'], $context))->toThrow(AuthException::class);
    $result = $invites->registerSocial($invitation['token'], $secret, ['name' => 'Invited'], $context);
    expect($result['invitation']->accepted_at)->not->toBeNull()->and($result['subject']->email)->toBe('new@example.test');
});

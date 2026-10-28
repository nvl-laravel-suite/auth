<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Services\AuthSocialLinks;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\ExternalIdentity;

beforeEach(function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
});

it('acquires, links, encrypts, and revokes an allowlisted social identity', function (): void {
    $user = $this->user();
    $links = app(AuthSocialLinks::class);
    $context = $this->authenticationContext();
    $intent = $links->beginLink($user, 'github', $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink, 'correct-password')->reveal(), $context);
    expect($intent['url'])->toBe('https://provider.example/authorize/github');
    $identity = $links->completeLink($user, 'github', $intent['intent']->reveal(), $context);
    expect($identity->subject_id)->toBe((string) $user->getKey())
        ->and($identity->getRawOriginal('provider_user_id'))->not->toBe('provider-user-123')
        ->and($identity->getRawOriginal('profile'))->not->toContain('source');
    expect($this->completeSocialAuthentication(app(AuthSocialAuthentication::class), 'github')->id)->toBe($identity->id);
    $links->unlink($user, $identity->identifier(), $this->recentGrant($user, RecentAuthenticationPurpose::SocialUnlink, 'correct-password')->reveal(), $context);
    expect($identity->refresh()->revoked_at)->not->toBeNull();
});

it('normalizes provider failures without retaining adapter secrets', function (): void {
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(failRedirect: true)));
    $context = $this->authenticationContext();
    try {
        app(AuthSocialAuthentication::class)->beginLogin('github', $context);
        $this->fail('The provider start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_provider_unavailable')->and($exception->getMessage())->not->toContain('credential leaked')->and($exception->getPrevious())->toBeNull();
    }
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(failUser: true)));
    $service = app(AuthSocialAuthentication::class);
    $intent = $service->beginLogin('github', $context);
    try {
        $service->completeLogin('github', $intent['intent']->reveal(), $context);
        $this->fail('The provider callback should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_authorization_failed')->and($exception->getMessage())->not->toContain('credential leaked')->and($exception->getPrevious())->toBeNull();
    }
});

it('links without email and admits only an active exact link for login', function (): void {
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('github', 'immutable-1'))));
    $context = $this->authenticationContext();
    $login = app(AuthSocialAuthentication::class);
    $intent = $login->beginLogin('github', $context);
    expect($login->completeLogin('github', $intent['intent']->reveal(), $context)['status'])->toBe('registration_required');
    $user = $this->user();
    $links = app(AuthSocialLinks::class);
    $intent = $links->beginLink($user, 'github', $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink, 'correct-password')->reveal(), $context);
    $linked = $links->completeLink($user, 'github', $intent['intent']->reveal(), $context);
    expect($this->completeSocialAuthentication($login, 'github')->id)->toBe($linked->id);
    $links->unlink($user, $linked->identifier(), $this->recentGrant($user, RecentAuthenticationPurpose::SocialUnlink, 'correct-password')->reveal(), $context);
    $revokedAt = $linked->refresh()->revoked_at;
    expect(fn () => $this->completeSocialAuthentication($login, 'github'))->toThrow(AuthException::class);
    $intent = $links->beginLink($user, 'github', $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink, 'correct-password')->reveal(), $context);
    expect(fn () => $links->completeLink($user, 'github', $intent['intent']->reveal(), $context))->toThrow(AuthException::class);
    expect($linked->refresh()->revoked_at->equalTo($revokedAt))->toBeTrue();
    $intent = $links->beginReconnect($user, 'github', $this->recentGrant($user, RecentAuthenticationPurpose::SocialReconnect, 'correct-password')->reveal(), $context);
    expect($links->completeReconnect($user, 'github', $intent['intent']->reveal(), $context)->revoked_at)->toBeNull();
});

it('rejects an identity whose returned provider does not match before persistence', function (): void {
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('google', 'immutable-1'))));
    $service = app(AuthSocialAuthentication::class);
    $context = $this->authenticationContext();
    $intent = $service->beginLogin('github', $context);
    expect(fn () => $service->completeLogin('github', $intent['intent']->reveal(), $context))->toThrow(AuthException::class);
    expect(SocialIdentity::query()->count())->toBe(0);
});

it('rejects reserved OAuth parameters at the provider configuration boundary', function (string $key): void {
    config(['nvl-auth.features.social_identities.settings.providers.github.parameters' => [$key => 'value']]);
    expect(fn () => app(AuthSocialAuthentication::class)->beginLogin('github', $this->authenticationContext()))->toThrow(AuthException::class);
})->with(['state', 'client_id', 'redirect_uri', 'response_type', 'scope', 'nonce', 'code_challenge', 'code_challenge_method', 'code_verifier']);

it('rejects changing the issuer on a retained link', function (): void {
    $user = $this->user();
    $this->seedSocialIdentity($user, new ExternalIdentity('github', 'subject', issuer: 'https://issuer.example'));
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('github', 'subject', issuer: 'https://other.example'))));
    $links = app(AuthSocialLinks::class);
    $context = $this->authenticationContext();
    $intent = $links->beginReconnect($user, 'github', $this->recentGrant($user, RecentAuthenticationPurpose::SocialReconnect, 'correct-password')->reveal(), $context);
    expect(fn () => $links->completeReconnect($user, 'github', $intent['intent']->reveal(), $context))->toThrow(AuthException::class);
});

it('rejects oversized external identity claims and invalid issuers', function (): void {
    expect(fn () => new ExternalIdentity('github', str_repeat('x', 16_384)))->toThrow(InvalidArgumentException::class);
    expect(fn () => new ExternalIdentity('google', 'subject', issuer: 'http://issuer.example'))->toThrow(InvalidArgumentException::class);
    expect(fn () => new ExternalIdentity('google', 'subject', issuer: 'https://issuer.example?query=1'))->toThrow(InvalidArgumentException::class);
});

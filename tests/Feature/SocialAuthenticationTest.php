<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Services\AuthSocialLinks;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;

beforeEach(function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.google' => ['callback_url' => 'https://app.example.test/callback', 'supports_reauthentication' => true]]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('google', 'immutable-123', email: 'user@example.test', emailVerified: true, emailVerificationSource: 'test'))));
});

it('returns a continuation for unknown identities without email based account linking', function (): void {
    $this->user();
    $service = app(AuthSocialAuthentication::class);
    $context = $this->authenticationContext();
    $start = $service->beginLogin('google', $context);
    $result = $service->completeLogin('google', $start['intent']->reveal(), $context);
    expect($result['status'])->toBe('registration_required')->and(SocialIdentity::query()->count())->toBe(0);
    expect(fn () => $service->completeLogin('google', $start['intent']->reveal(), $context))->toThrow(AuthException::class);
});

it('binds linking to the initiating subject purpose and revision and permits linked social step up', function (): void {
    $user = $this->user();
    $other = $this->user('other@example.test');
    $context = $this->authenticationContext();
    $links = app(AuthSocialLinks::class);
    $auth = app(AuthSocialAuthentication::class);
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink)->reveal();
    $start = $links->beginLink($user, 'google', $grant, $context);
    expect(fn () => $auth->completeLogin('google', $start['intent']->reveal(), $context))->toThrow(AuthException::class);
    expect(fn () => $links->completeLink($other, 'google', $start['intent']->reveal(), $context))->toThrow(AuthException::class);
    $identity = $links->completeLink($user, 'google', $start['intent']->reveal(), $context);
    expect($identity->subject_id)->toBe((string) $user->getKey());
    $login = $auth->beginLogin('google', $context);
    expect($auth->completeLogin('google', $login['intent']->reveal(), $context)['subject']->getAuthIdentifier())->toBe($user->getAuthIdentifier());
    $reauth = $auth->beginReauthentication($user, 'google', $context);
    $proof = $auth->completeReauthentication($user, 'google', $reauth['intent']->reveal(), $context);
    $recent = app(AuthReauthentication::class)->confirm($user, ['socialProof' => $proof->reveal()], RecentAuthenticationPurpose::SocialUnlink, $context);
    expect($recent->reveal())->toHaveLength(64);
    $links->unlink($user, $identity->identifier(), $recent->reveal(), $context);
    $login = $auth->beginLogin('google', $context);
    expect(fn () => $auth->completeLogin('google', $login['intent']->reveal(), $context))->toThrow(AuthException::class);
});

it('rejects substituted browser bindings and expired social intents', function (): void {
    $auth = app(AuthSocialAuthentication::class);
    $context = $this->authenticationContext();
    $start = $auth->beginLogin('google', $context);
    expect(fn () => $auth->completeLogin('google', $start['intent']->reveal(), new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'other-browser')))->toThrow(AuthException::class);
    $this->travel(301)->seconds();
    expect(fn () => $auth->completeLogin('google', $start['intent']->reveal(), $context))->toThrow(AuthException::class);
});

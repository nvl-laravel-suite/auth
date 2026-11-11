<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
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

it('refuses to link a provider identity that already belongs to another principal', function (): void {
    $user = $this->user();
    $other = $this->user('other@example.test');
    $owned = $this->seedSocialIdentity($other, new ExternalIdentity('google', 'immutable-123'));
    $context = $this->authenticationContext();
    $links = app(AuthSocialLinks::class);
    $start = $links->beginLink($user, 'google', $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink)->reveal(), $context);

    try {
        $links->completeLink($user, 'google', $start['intent']->reveal(), $context);
        $this->fail('A provider identity owned by another principal was linked.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_identity_conflict');
    }

    $login = app(AuthSocialAuthentication::class)->beginLogin('google', $context);

    expect(SocialIdentity::query()->sole()->is($owned))->toBeTrue()
        ->and($owned->refresh()->subject_id)->toBe((string) $other->getKey())
        ->and(app(AuthSocialAuthentication::class)->completeLogin('google', $login['intent']->reveal(), $context)['subject']->getAuthIdentifier())->toBe($other->getAuthIdentifier());
});

it('refuses to unlink the last usable primary authentication method', function (): void {
    $user = $this->user();
    $user->update(['password' => null]);
    $identity = $this->seedSocialIdentity($user, new ExternalIdentity('google', 'immutable-123'));
    $context = $this->authenticationContext();
    $auth = app(AuthSocialAuthentication::class);
    $reauth = $auth->beginReauthentication($user, 'google', $context);
    $proof = $auth->completeReauthentication($user, 'google', $reauth['intent']->reveal(), $context);
    $recent = app(AuthReauthentication::class)->confirm($user, ['socialProof' => $proof->reveal()], RecentAuthenticationPurpose::SocialUnlink, $context);

    try {
        app(AuthSocialLinks::class)->unlink($user, $identity->identifier(), $recent->reveal(), $context);
        $this->fail('The last usable primary authentication method was unlinked.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('last_authentication_method');
    }

    expect($identity->refresh()->revoked_at)->toBeNull();
});

it('keeps social intents, provider identifiers, grants and proofs out of the audit trail', function (): void {
    $user = $this->user();
    $context = $this->authenticationContext();
    $links = app(AuthSocialLinks::class);
    $auth = app(AuthSocialAuthentication::class);
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink)->reveal();
    $link = $links->beginLink($user, 'google', $grant, $context);
    $identity = $links->completeLink($user, 'google', $link['intent']->reveal(), $context);
    $login = $auth->beginLogin('google', $context);
    $proof = $auth->completeLogin('google', $login['intent']->reveal(), $context)['proof']->reveal();
    $unlink = $this->recentGrant($user, RecentAuthenticationPurpose::SocialUnlink)->reveal();
    $links->unlink($user, $identity->identifier(), $unlink, $context);
    $audits = AuthAudit::query()->get();
    $trail = json_encode($audits->map(static fn (AuthAudit $audit): array => [$audit->action, $audit->outcome, $audit->metadata])->all(), JSON_THROW_ON_ERROR);

    expect($audits->pluck('action')->all())->toContain('social_identity.linked', 'social_identity.revoked');

    foreach ([$grant, $unlink, $link['intent']->reveal(), $login['intent']->reveal(), $proof, 'immutable-123', 'correct-password'] as $secret) {
        expect($trail)->not->toContain($secret);
    }
});

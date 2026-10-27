<?php

declare(strict_types=1);

use Nvl\Auth\Adapters\Laravel\EloquentAuthSubjectResolver;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\Tests\Fixtures\TestSocialSubjectResolver;
use Nvl\Auth\ValueObjects\ExternalIdentity;

it('acquires, links, encrypts, and revokes an allowlisted social identity', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', [
        'callback_url' => 'https://app.example.test/callback',
        'scopes' => ['read:user'],
        'parameters' => [],
    ]);
    $user = $this->user();
    $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
    $this->app->instance(SocialSubjectResolver::class, new TestSocialSubjectResolver($user));

    expect(app(AuthSocialIdentities::class)->startAuthorization('github'))
        ->toBe('https://provider.example/authorize/github');

    $identity = app(AuthSocialIdentities::class)->completeAuthorization('github');

    expect($identity)->toBeInstanceOf(SocialIdentity::class)
        ->and($identity->subject_id)->toBe((string) $user->getKey())
        ->and($identity->getRawOriginal('provider_user_id'))->not->toBe('provider-user-123')
        ->and($identity->getRawOriginal('profile'))->not->toContain('source');

    app(AuthSocialIdentities::class)->revoke($user, $identity);

    expect($identity->refresh()->revoked_at)->not->toBeNull();
});

it('normalizes provider failures without leaking adapter details', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', [
        'callback_url' => 'https://app.example.test/callback',
        'scopes' => [],
        'parameters' => [],
    ]);

    $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(failRedirect: true)));

    try {
        app(AuthSocialIdentities::class)->startAuthorization('github');
        $this->fail('The provider start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_provider_unavailable')
            ->and($exception->getMessage())->not->toContain('credential leaked')
            ->and($exception->getPrevious()?->getMessage())->toContain('credential leaked');
    }

    $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(failUser: true)));

    try {
        app(AuthSocialIdentities::class)->completeAuthorization('github', $this->user());
        $this->fail('The provider callback should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_authorization_failed')
            ->and($exception->getMessage())->not->toContain('credential leaked')
            ->and($exception->getPrevious()?->getMessage())->toContain('credential leaked');
    }
});

it('permits an authenticated subject to link without email but rejects unknown unauthenticated identities', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', ['scopes' => [], 'parameters' => []]);
    $external = new ExternalIdentity('github', 'immutable-1');
    $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: $external)));
    $this->app->instance(AuthSubjectResolver::class, new EloquentAuthSubjectResolver);
    $this->app->instance(SocialSubjectResolver::class, Mockery::mock(SocialSubjectResolver::class));
    $service = app(AuthSocialIdentities::class);

    expect(fn () => $service->completeAuthorization('github'))->toThrow(AuthException::class, 'did not prove');
    $user = $this->user();
    $linked = $service->completeAuthorization('github', $user);
    expect($service->completeAuthorization('github')->id)->toBe($linked->id);
    $service->revoke($user, $linked);
    expect(fn () => $service->completeAuthorization('github'))->toThrow(AuthException::class, 'did not prove');
});

it('rejects an identity whose returned provider does not match before persistence', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', ['scopes' => [], 'parameters' => []]);
    $external = new ExternalIdentity('google', 'immutable-1');
    $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: $external)));

    expect(fn () => app(AuthSocialIdentities::class)->completeAuthorization('github', $this->user()))->toThrow(AuthException::class);
    expect(SocialIdentity::query()->count())->toBe(0);
});

it('rejects reserved OAuth parameters at the provider configuration boundary', function (string $key): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', ['scopes' => [], 'parameters' => [$key => 'value']]);
    expect(fn () => app(AuthSocialIdentities::class)->startAuthorization('github'))->toThrow(AuthException::class);
})->with(['state', 'client_id', 'redirect_uri', 'response_type', 'scope', 'nonce', 'code_challenge', 'code_challenge_method', 'code_verifier']);

it('rejects changing the issuer on a retained link', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    $service = app(AuthSocialIdentities::class);
    $user = $this->user();
    $service->link($user, new ExternalIdentity('google', 'subject', issuer: 'https://issuer.example'));
    expect(fn () => $service->link($user, new ExternalIdentity('google', 'subject', issuer: 'https://other.example')))->toThrow(AuthException::class);
});

it('rejects oversized external identity claims and invalid issuers', function (): void {
    expect(fn () => new ExternalIdentity('github', str_repeat('x', 16_384)))->toThrow(InvalidArgumentException::class);
    expect(fn () => new ExternalIdentity('google', 'subject', issuer: 'http://issuer.example'))->toThrow(InvalidArgumentException::class);
    expect(fn () => new ExternalIdentity('google', 'subject', issuer: 'https://issuer.example?query=1'))->toThrow(InvalidArgumentException::class);
});

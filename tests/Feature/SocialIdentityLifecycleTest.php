<?php

declare(strict_types=1);

use Nvl\Auth\Actions\SocialIdentities\CompleteSocialAuthorizationAction;
use Nvl\Auth\Actions\SocialIdentities\RevokeSocialIdentityAction;
use Nvl\Auth\Actions\SocialIdentities\StartSocialAuthorizationAction;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialSubjectResolver;

it('acquires, links, encrypts, and revokes an allowlisted social identity', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', [
        'callback_url' => 'https://app.example.test/callback',
        'scopes' => ['read:user'],
        'parameters' => [],
    ]);
    $user = $this->user();
    $this->app->singleton(SocialIdentityProvider::class, TestSocialIdentityProvider::class);
    $this->app->instance(SocialSubjectResolver::class, new TestSocialSubjectResolver($user));

    expect(app(StartSocialAuthorizationAction::class)->execute('github'))
        ->toBe('https://provider.example/authorize/github');

    $identity = app(CompleteSocialAuthorizationAction::class)->execute('github');

    expect($identity)->toBeInstanceOf(SocialIdentity::class)
        ->and($identity->subject_id)->toBe((string) $user->getKey())
        ->and($identity->getRawOriginal('provider_user_id'))->not->toBe('provider-user-123')
        ->and($identity->getRawOriginal('profile'))->not->toContain('source');

    app(RevokeSocialIdentityAction::class)->execute($user, $identity);

    expect($identity->refresh()->revoked_at)->not->toBeNull();
});

it('normalizes provider failures without leaking adapter details', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', [
        'callback_url' => 'https://app.example.test/callback',
        'scopes' => [],
        'parameters' => [],
    ]);

    $this->app->instance(SocialIdentityProvider::class, new TestSocialIdentityProvider(failRedirect: true));

    try {
        app(StartSocialAuthorizationAction::class)->execute('github');
        $this->fail('The provider start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_provider_unavailable')
            ->and($exception->getMessage())->not->toContain('credential leaked')
            ->and($exception->getPrevious()?->getMessage())->toContain('credential leaked');
    }

    $this->app->instance(SocialIdentityProvider::class, new TestSocialIdentityProvider(failUser: true));

    try {
        app(CompleteSocialAuthorizationAction::class)->execute('github', $this->user());
        $this->fail('The provider callback should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_authorization_failed')
            ->and($exception->getMessage())->not->toContain('credential leaked')
            ->and($exception->getPrevious()?->getMessage())->toContain('credential leaked');
    }
});

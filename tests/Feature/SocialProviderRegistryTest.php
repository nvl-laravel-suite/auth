<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\SocialProviderRegistry;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;

it('discovers safe allowlisted connections without acquiring claims and rejects disabled aliases', function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers' => [
        'google' => ['label' => 'Google', 'client_secret' => 'must-not-leak', 'supports_reauthentication' => true],
        'github' => ['label' => 'GitHub', 'enabled' => false],
    ]]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
    $registry = app(SocialProviderRegistry::class);
    expect($registry->providers())->toBe([
        'google' => ['enabled' => true, 'label' => 'Google', 'supportsReauthentication' => true],
        'github' => ['enabled' => false, 'label' => 'GitHub', 'supportsReauthentication' => false],
    ]);
    $registry->assertAvailable('google');
    expect(fn () => $registry->assertAvailable('github'))->toThrow(AuthException::class);
    expect(fn () => $registry->assertAvailable('unregistered'))->toThrow(AuthException::class);
});

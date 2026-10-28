<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite;

use Illuminate\Contracts\Container\Container;
use Laravel\Socialite\Contracts\Provider;
use Laravel\Socialite\Two\AbstractProvider;
use Nvl\Auth\Adapters\Socialite\Contracts\SocialiteDriverFactory;
use Nvl\Auth\Adapters\Socialite\Contracts\SocialiteEmailVerification;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;

/**
 * Optional class-string composition; never retains a Socialite manager or driver.
 *
 * @api
 */
final readonly class SocialiteProviderFactory implements SocialIdentityProviderFactory
{
    public function __construct(private AuthConfiguration $configuration, private Container $container) {}

    public function make(string $provider): SocialIdentityProvider
    {
        if (! interface_exists(Provider::class)) {
            throw AuthException::invalidConfiguration('The selected social adapter requires laravel/socialite.');
        }
        $settings = $this->configuration->get("features.social_identities.settings.providers.{$provider}");
        $factory = is_array($settings) ? ($settings['driver_factory'] ?? null) : null;
        if (! is_array($settings) || ($settings['enabled'] ?? true) !== true || ! is_string($factory) || ! is_a($factory, SocialiteDriverFactory::class, true)) {
            throw AuthException::invalidConfiguration('A social connection requires a fresh SocialiteDriverFactory.');
        }
        $resolved = $this->container->make($factory);
        if (! $resolved instanceof SocialiteDriverFactory) {
            throw AuthException::invalidConfiguration('Invalid resolved social driver factory.');
        }
        $driver = $resolved->make($provider);
        $policy = $settings['email_verification'] ?? null;
        if ($policy !== null && (! is_string($policy) || ! is_a($policy, SocialiteEmailVerification::class, true))) {
            throw AuthException::invalidConfiguration('Invalid provider email provenance policy.');
        }
        $issuer = $settings['issuer'] ?? null;
        if ($issuer !== null && ! is_string($issuer)) {
            throw AuthException::invalidConfiguration('Invalid fixed social issuer.');
        }
        if (($settings['pkce'] ?? false) === true) {
            if (! $driver instanceof AbstractProvider) {
                throw AuthException::invalidConfiguration('PKCE requires an OAuth2 driver.');
            }
            $driver->enablePKCE();
        }
        $verification = $policy === null ? null : $this->container->make($policy);
        if ($verification !== null && ! $verification instanceof SocialiteEmailVerification) {
            throw AuthException::invalidConfiguration('Invalid resolved email provenance policy.');
        }

        return new SocialiteIdentityProvider($driver, $provider, $verification, $issuer);
    }
}

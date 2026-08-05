<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite;

use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\Contracts\Provider;
use Laravel\Socialite\Two\AbstractProvider;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Acquires external identities through optional Laravel Socialite.
 */
final readonly class SocialiteIdentityProvider implements SocialIdentityProvider
{
    /**
     * Create the Socialite adapter.
     */
    public function __construct(private Factory $socialite) {}

    /**
     * Build a stateful provider authorization URL.
     */
    public function redirectUrl(
        string $provider,
        ?string $callbackUrl,
        array $scopes,
        array $parameters,
    ): string {
        $driver = $this->driver($provider, $callbackUrl);

        if ($scopes !== [] || $parameters !== []) {
            if (! $driver instanceof AbstractProvider) {
                throw AuthException::invalidConfiguration(
                    "Socialite provider [{$provider}] does not support OAuth2 scope or parameter configuration.",
                );
            }

            if ($scopes !== []) {
                $driver->scopes($scopes);
            }

            if ($parameters !== []) {
                $driver->with($parameters);
            }
        }

        return $driver->redirect()->getTargetUrl();
    }

    /**
     * Acquire normalized callback claims without retaining OAuth tokens.
     */
    public function user(string $provider, ?string $callbackUrl): ExternalIdentity
    {
        $user = $this->driver($provider, $callbackUrl)->user();
        $providerUserId = $user->getId();

        if (trim($providerUserId) === '') {
            throw AuthException::invalidConfiguration(
                "Socialite provider [{$provider}] returned no immutable user identifier.",
            );
        }

        return new ExternalIdentity(
            provider: $provider,
            providerUserId: $providerUserId,
            email: $user->getEmail(),
            name: $user->getName(),
            avatar: $user->getAvatar(),
            profile: ['nickname' => $user->getNickname()],
        );
    }

    /**
     * Resolve a stateful OAuth2 driver.
     */
    private function driver(string $provider, ?string $callbackUrl): Provider
    {
        if (! interface_exists(Factory::class)) {
            throw AuthException::invalidConfiguration(
                'Social identities require laravel/socialite.',
            );
        }

        $driver = $this->socialite->driver($provider);

        if ($callbackUrl !== null) {
            if (! $driver instanceof AbstractProvider) {
                throw AuthException::invalidConfiguration(
                    "Socialite provider [{$provider}] does not support OAuth2 callback configuration.",
                );
            }

            $driver->redirectUrl($callbackUrl);
        }

        return $driver;
    }
}

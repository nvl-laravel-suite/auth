<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite;

use Laravel\Socialite\AbstractUser;
use Laravel\Socialite\Contracts\Provider;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\GithubProvider;
use Laravel\Socialite\Two\GoogleProvider;
use Nvl\Auth\Adapters\Socialite\Contracts\SocialiteEmailVerification;
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
    public function __construct(private Provider $providerDriver, private string $providerName, private ?SocialiteEmailVerification $emailVerification = null, private ?string $issuer = null) {}

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
                if (array_intersect(array_map('strtolower', array_keys($parameters)), ['state', 'client_id', 'client_secret', 'redirect_uri', 'response_type', 'scope', 'nonce', 'code_challenge', 'code_challenge_method', 'code_verifier']) !== []) {
                    throw AuthException::invalidConfiguration(
                        'OAuth protocol parameters are reserved and cannot be replaced by provider parameters.',
                    );
                }
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
        $providerUserId = $this->normalizeIdentifier($user->getId(), $provider);

        $email = $user->getEmail();
        if (! $user instanceof AbstractUser) {
            throw AuthException::invalidConfiguration(
                "Socialite provider [{$provider}] must return a standard Socialite user with raw claims.",
            );
        }

        $policy = $this->emailVerification;
        if ($policy === null && get_class($this->providerDriver) === GoogleProvider::class) {
            $policy = new GoogleEmailVerification;
        } elseif ($policy === null && get_class($this->providerDriver) === GithubProvider::class
            && in_array('user:email', $this->providerDriver->getScopes(), true)) {
            $policy = new GithubEmailVerification;
        }
        $verification = $policy?->verification($user) ?? ['verified' => false, 'source' => null];

        return new ExternalIdentity(
            provider: $provider,
            providerUserId: $providerUserId,
            email: $email,
            name: $user->getName(),
            avatar: $user->getAvatar(),
            profile: ['nickname' => $user->getNickname()],
            emailVerified: $verification['verified'],
            emailVerificationSource: $verification['source'],
            issuer: $this->issuer,
        );
    }

    /** Normalize the SDK's untyped identifier without numeric coercion. */
    private function normalizeIdentifier(mixed $identifier, string $provider): string
    {
        if ((! is_string($identifier) && ! is_int($identifier)) || trim((string) $identifier) === '') {
            throw AuthException::invalidConfiguration(
                "Socialite provider [{$provider}] returned no immutable user identifier.",
            );
        }

        return (string) $identifier;
    }

    /**
     * Resolve a stateful OAuth2 driver.
     */
    private function driver(string $provider, ?string $callbackUrl): Provider
    {
        if (! interface_exists(Provider::class)) {
            throw AuthException::invalidConfiguration(
                'Social identities require laravel/socialite.',
            );
        }

        if ($provider !== $this->providerName) {
            throw AuthException::invalidConfiguration('The supplied Socialite driver belongs to a different provider.');
        }
        $driver = $this->providerDriver;

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

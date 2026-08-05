<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Fails closed until the host configures an external identity adapter.
 */
final class UnavailableSocialIdentityProvider implements SocialIdentityProvider
{
    /** {@inheritDoc} */
    public function redirectUrl(
        string $provider,
        ?string $callbackUrl,
        array $scopes,
        array $parameters,
    ): string {
        throw $this->unavailable();
    }

    /** {@inheritDoc} */
    public function user(string $provider, ?string $callbackUrl): ExternalIdentity
    {
        throw $this->unavailable();
    }

    /**
     * Build the configuration failure.
     */
    private function unavailable(): AuthException
    {
        return AuthException::invalidConfiguration(
            'Social identities require a configured SocialIdentityProvider such as the Socialite adapter.',
        );
    }
}

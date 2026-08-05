<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\ExternalIdentity;

/**
 * Adapts an external identity acquisition provider such as Laravel Socialite.
 */
interface SocialIdentityProvider
{
    /**
     * Build the provider authorization URL.
     *
     * @param  list<string>  $scopes
     * @param  array<string, scalar>  $parameters
     */
    public function redirectUrl(
        string $provider,
        ?string $callbackUrl,
        array $scopes,
        array $parameters,
    ): string;

    /**
     * Acquire the verified callback identity.
     */
    public function user(string $provider, ?string $callbackUrl): ExternalIdentity;
}

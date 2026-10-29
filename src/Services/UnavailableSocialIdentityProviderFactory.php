<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Exceptions\AuthException;

/** Denies acquisition until a host provider factory is configured. *
 * @internal
 */
final class UnavailableSocialIdentityProviderFactory implements SocialIdentityProviderFactory
{
    public function make(string $provider): SocialIdentityProvider
    {
        throw AuthException::invalidConfiguration('Social identities require a configured SocialIdentityProviderFactory.');
    }
}

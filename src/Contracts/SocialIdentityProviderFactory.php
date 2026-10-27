<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Constructs a fresh identity provider for each operation.
 *
 * @api
 */
interface SocialIdentityProviderFactory
{
    /** Construct a provider from the current operation context. */
    public function make(string $provider): SocialIdentityProvider;
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;

/** Supplies controllable providers to lifecycle tests. */
final class TestSocialIdentityProviderFactory implements SocialIdentityProviderFactory
{
    public function __construct(private ?TestSocialIdentityProvider $provider = null) {}

    public function make(string $provider): SocialIdentityProvider
    {
        return $this->provider ?? new TestSocialIdentityProvider;
    }
}

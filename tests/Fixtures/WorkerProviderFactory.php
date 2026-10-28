<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Adapters\Socialite\SocialiteIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;

/** Constructs an SDK provider from the current worker request. */
final class WorkerProviderFactory implements SocialIdentityProviderFactory
{
    public function make(string $provider): SocialIdentityProvider
    {
        return new SocialiteIdentityProvider(new WorkerGithubProvider(app('request'), 'client', 'secret', 'https://example.test/callback'), $provider);
    }
}

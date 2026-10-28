<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite\Contracts;

use Laravel\Socialite\Contracts\Provider;

/** Consumer constructs a new SDK driver with its current request and secret configuration. @api */
interface SocialiteDriverFactory
{
    public function make(string $connection): Provider;
}

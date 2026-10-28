<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite\Contracts;

use Laravel\Socialite\AbstractUser;

/** Provider-specific provenance for Socialite email claims. */
interface SocialiteEmailVerification
{
    /** @return array{verified: bool, source: string|null} */
    public function verification(AbstractUser $user): array;
}

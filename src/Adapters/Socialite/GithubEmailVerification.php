<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite;

use Laravel\Socialite\AbstractUser;
use Nvl\Auth\Adapters\Socialite\Contracts\SocialiteEmailVerification;

/** Interprets email returned by Socialite's verified-primary GitHub endpoint. */
final class GithubEmailVerification implements SocialiteEmailVerification
{
    public function verification(AbstractUser $user): array
    {
        $verified = is_string($user->getEmail()) && trim($user->getEmail()) !== '';

        return ['verified' => $verified, 'source' => $verified ? 'github.user.emails.verified_primary' : null];
    }
}

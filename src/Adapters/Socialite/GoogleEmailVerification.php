<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Socialite;

use Laravel\Socialite\AbstractUser;
use Nvl\Auth\Adapters\Socialite\Contracts\SocialiteEmailVerification;

/** Interprets the Google userinfo email_verified claim. */
final class GoogleEmailVerification implements SocialiteEmailVerification
{
    public function verification(AbstractUser $user): array
    {
        $email = $user->getEmail();
        $verified = is_string($email) && trim($email) !== '' && ($user->getRaw()['email_verified'] ?? null) === true;

        return ['verified' => $verified, 'source' => $verified ? 'google.userinfo.email_verified' : null];
    }
}

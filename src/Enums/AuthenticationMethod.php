<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Native primary verification methods; recovery is never a primary method.
 *
 * @api
 */
enum AuthenticationMethod: string
{
    case Password = 'password';
    case EmailLink = 'email_link';
    case EmailCode = 'email_code';
    case Social = 'social';
    case Passkey = 'passkey';

    public function purpose(): AuthenticationPurpose
    {
        return match ($this) {
            self::Password => AuthenticationPurpose::CredentialLogin,
            self::Social => AuthenticationPurpose::SocialLogin,
            default => AuthenticationPurpose::PasswordlessLogin,
        };
    }
}

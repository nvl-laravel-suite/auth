<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Declares the bounded owner selection authentication bootstrap operations.
 *
 * @api
 */
enum OwnerAuthenticationPurpose: string
{
    case Login = 'login';
    case SocialLogin = 'social_login';
    case SocialLink = 'social_link';
    case MagicLink = 'magic_link';
    case SecurityCode = 'security_code';
    case PasskeyLogin = 'passkey_login';
    case Invitation = 'invitation';
}

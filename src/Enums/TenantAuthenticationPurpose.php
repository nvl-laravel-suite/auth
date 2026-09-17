<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/** Declares the bounded tenant-aware authentication bootstrap operations. */
enum TenantAuthenticationPurpose: string
{
    case Login = 'login';
    case SocialLogin = 'social_login';
    case SocialLink = 'social_link';
    case MagicLink = 'magic_link';
    case SecurityCode = 'security_code';
    case PasskeyLogin = 'passkey_login';
    case Invitation = 'invitation';
}

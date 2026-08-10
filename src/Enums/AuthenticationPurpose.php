<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies subject-policy checkpoints shared by authentication flows.
 */
enum AuthenticationPurpose: string
{
    case CredentialLogin = 'credential_login';
    case PasswordlessLogin = 'passwordless_login';
    case SocialLogin = 'social_login';
    case PasswordReset = 'password_reset';
}

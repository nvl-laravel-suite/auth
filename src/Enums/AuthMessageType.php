<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies transport-neutral messages emitted by Auth.
 */
enum AuthMessageType: string
{
    case Invitation = 'invitation';
    case MagicLink = 'magic_link';
    case SecurityCode = 'security_code';
    case PasswordReset = 'password_reset';
    case EmailVerification = 'email_verification';
}

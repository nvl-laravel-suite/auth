<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies transport-neutral messages emitted by Auth.
 *
 * @api
 */
enum AuthMessageType: string
{
    case RegistrationEmailVerification = 'registration_email_verification';
    case EmailChangeVerification = 'email_change_verification';
    case EmailChangeNotification = 'email_change_notification';
    case Invitation = 'invitation';
    case MagicLink = 'magic_link';
    case SecurityCode = 'security_code';
    case PasswordReset = 'password_reset';
    case EmailVerification = 'email_verification';
}

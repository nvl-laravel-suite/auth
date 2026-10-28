<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Closed native self-service authorization purposes.
 *
 * @api
 */
enum RecentAuthenticationPurpose: string
{
    case PasswordChange = 'password_change';
    case EmailChange = 'email_change';
    case AccountDeletion = 'account_deletion';
    case SocialLink = 'social_link';
    case SocialUnlink = 'social_unlink';
    case SocialReconnect = 'social_reconnect';
    case FactorEnrollment = 'factor_enrollment';
    case FactorRemoval = 'factor_removal';
    case RecoveryRegeneration = 'recovery_regeneration';
    case SessionRevocation = 'session_revocation';
    case ImpersonationStart = 'impersonation_start';
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies every independently configurable Auth capability.
 */
enum AuthFeature: string
{
    case Authentication = 'authentication';
    case PrincipalManagement = 'principal_management';
    case Password = 'password';
    case EmailVerification = 'email_verification';
    case MagicLinks = 'magic_links';
    case SecurityCodes = 'security_codes';
    case Invitations = 'invitations';
    case Totp = 'totp';
    case Passkeys = 'passkeys';
    case RecoveryCodes = 'recovery_codes';
    case SocialIdentities = 'social_identities';
    case Clients = 'clients';
    case Sessions = 'sessions';
    case ApiTokens = 'api_tokens';
    case Rbac = 'rbac';
    case Audit = 'audit';
}

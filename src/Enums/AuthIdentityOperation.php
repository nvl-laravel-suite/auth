<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/** Enumerates the narrow central-identity operations admitted with Tenancy enabled. */
enum AuthIdentityOperation: string
{
    case Login = 'login';
    case Logout = 'logout';
    case Recovery = 'recovery';
    case VerifyEmail = 'verify_email';
    case Profile = 'profile';
    case Password = 'password';
    case Mfa = 'mfa';
    case SocialIdentity = 'social_identity';
    case MembershipDiscovery = 'membership_discovery';
}

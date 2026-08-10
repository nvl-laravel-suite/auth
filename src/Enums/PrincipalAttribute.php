<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/** Canonical principal fields understood by package orchestration. */
enum PrincipalAttribute: string
{
    case Id = 'id';
    case Name = 'name';
    case Email = 'email';
    case EmailVerifiedAt = 'email_verified_at';
    case Password = 'password';
    case Active = 'active';
    case Locale = 'locale';
    case Timezone = 'timezone';
    case Profile = 'profile';
    case Preferences = 'preferences';
    case LastLoginAt = 'last_login_at';
    case LastLoginIp = 'last_login_ip';
    case LockedUntil = 'locked_until';
    case RememberToken = 'remember_token';
    case CreatedAt = 'created_at';
    case UpdatedAt = 'updated_at';
    case DeletedAt = 'deleted_at';
}

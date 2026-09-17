<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/** Describes whether a tenant membership currently admits its principal. */
enum MembershipStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
    case Revoked = 'revoked';
}

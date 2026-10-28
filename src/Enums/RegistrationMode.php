<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Native registration admission mode.
 *
 * @api
 */
enum RegistrationMode: string
{
    case Closed = 'closed';
    case InvitationOnly = 'invitation_only';
    case Open = 'open';
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/** Service-selected social callback authority. @api */
enum SocialIntentPurpose: string
{
    case Login = 'login';
    case Link = 'link';
    case Reconnect = 'reconnect';
    case Reauthentication = 'reauthentication';
    case Registration = 'registration';
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Captures the initiating operation, never a completion choice.
 *
 * @api
 */
enum AuthenticationDestination: string
{
    case Session = 'session';
    case ApiToken = 'api_token';
    case Reauthentication = 'reauthentication';
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Native registration workflow fact; never caller-asserted proof.
 *
 * @api
 */
enum RegistrationMethod: string
{
    case Password = 'password';
    case Social = 'social';
}

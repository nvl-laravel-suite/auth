<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Identifies supported bounded bulk principal mutations.
 */
enum UserBulkOperation: string
{
    case Enable = 'enable';
    case Disable = 'disable';
    case Delete = 'delete';
    case Restore = 'restore';
}

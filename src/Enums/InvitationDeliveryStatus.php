<?php

declare(strict_types=1);

namespace Nvl\Auth\Enums;

/**
 * Describes the current host-reported outcome for one invitation delivery.
 */
enum InvitationDeliveryStatus: string
{
    case Pending = 'pending';
    case Delivered = 'delivered';
    case Failed = 'failed';
}

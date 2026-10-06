<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Carbon\CarbonImmutable;
use Nvl\Auth\Enums\InvitationDeliveryStatus;

/**
 * Defines the record invitation delivery outcome use-case boundary.
 *
 * @api
 */
interface RecordInvitationDeliveryOutcomeContract
{
    /**
     * Record a delivered or failed outcome idempotently.
     */
    public function execute(
        string $invitationId,
        string $messageId,
        InvitationDeliveryStatus $status,
        CarbonImmutable $occurredAt,
        ?string $failureCode = null,
    ): void;
}

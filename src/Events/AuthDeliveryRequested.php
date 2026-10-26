<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Support\Contracts\DomainEvent;
use Nvl\Support\Ownership\Contracts\OwnershipQueuedJob;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

/**
 * Requests host delivery after the source commit with immutable native admission facts.
 *
 * @api
 */
final readonly class AuthDeliveryRequested implements DomainEvent, OwnershipQueuedJob
{
    public function __construct(public AuthDeliveryRequest $request, private OwnershipJobEnvelope $ownership, public int $schemaVersion = 1) {}

    public function ownershipJobEnvelope(): OwnershipJobEnvelope
    {
        return $this->ownership;
    }

    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

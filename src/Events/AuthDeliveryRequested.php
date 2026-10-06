<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Support\Contracts\DomainEvent;
use Nvl\Support\Tenancy\Contracts\TenantQueuedJob;
use Nvl\Support\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Support\Tenancy\ValueObjects\TenantJobEnvelope;

/**
 * Requests host-owned delivery after Auth state has committed.
 *
 * @api
 */
final class AuthDeliveryRequested implements DomainEvent, TenantQueuedJob
{
    private ?TenantJobEnvelope $envelope = null;

    /**
     * Create a transport-neutral delivery event.
     */
    public function __construct(public readonly AuthDeliveryRequest $request, public readonly int $schemaVersion = 1)
    {
        $this->envelope = $this->eventContext()->envelope();
    }

    public function tenantJobEnvelope(): TenantJobEnvelope
    {
        return $this->envelope instanceof TenantJobEnvelope
            ? $this->envelope
            : $this->eventContext()->envelope();
    }

    private function eventContext(): AuthEventContext
    {
        return $this->request->eventContext
            ?? throw new TenantBoundaryViolation('Queued Auth delivery requires captured event context.');
    }

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

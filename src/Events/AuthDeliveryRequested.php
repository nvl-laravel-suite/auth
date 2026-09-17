<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Tenancy\Contracts\TenantQueuedJob;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\ValueObjects\TenantJobEnvelope;

/**
 * Requests host-owned delivery after Auth state has committed.
 */
final class AuthDeliveryRequested implements ShouldDispatchAfterCommit, TenantQueuedJob
{
    use Dispatchable;

    private ?TenantJobEnvelope $envelope = null;

    /**
     * Create a transport-neutral delivery event.
     */
    public function __construct(public readonly AuthDeliveryRequest $request)
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
}

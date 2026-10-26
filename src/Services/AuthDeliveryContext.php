<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipQueueContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnershipJobEnvelope;

/**
 * Capture source-time admission for queued delivery without inferring a host principal.
 *
 * @internal
 */
final readonly class AuthDeliveryContext
{
    /** Native Auth operation. */
    public function __construct(private OwnershipContext $context, private OwnershipQueueContext $queues) {}

    /** Native Auth operation. */
    public function capture(bool $identity = false): OwnershipJobEnvelope
    {
        return $identity || $this->context->snapshot()->mode === OwnershipContextMode::Unresolved ? $this->queues->captureUnowned() : OwnershipJobEnvelope::capture($this->context);
    }
}

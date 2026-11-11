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
    /** Create the delivery ownership-context capturer. */
    public function __construct(private OwnershipContext $context, private OwnershipQueueContext $queues) {}

    /** Capture the current ownership context, or an unowned envelope for identity deliveries and unresolved contexts. */
    public function capture(bool $identity = false): OwnershipJobEnvelope
    {
        return $identity || $this->context->snapshot()->mode === OwnershipContextMode::Unresolved ? $this->queues->captureUnowned() : OwnershipJobEnvelope::capture($this->context);
    }
}

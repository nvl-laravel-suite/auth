<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;

/**
 * Requests host-owned delivery after Auth state has committed.
 */
final class AuthDeliveryRequested implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create a transport-neutral delivery event.
     */
    public function __construct(public readonly AuthDeliveryRequest $request) {}
}

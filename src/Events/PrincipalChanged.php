<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Publishes a committed principal mutation for external integrations.
 */
final class PrincipalChanged implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create the principal event.
     *
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $operation,
        public readonly array $payload = [],
    ) {}
}

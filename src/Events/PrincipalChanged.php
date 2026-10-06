<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes a committed principal mutation for external integrations.
 *
 * @api
 */
final class PrincipalChanged implements DomainEvent
{
    /**
     * Create the principal event.
     *
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $operation,
        public readonly array $payload = [],
        public readonly ?AuthEventContext $context = null,
        public readonly int $schemaVersion = 1,
    ) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

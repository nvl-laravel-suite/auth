<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes a committed role, permission, or assignment mutation.
 *
 * @api
 */
final class RbacChanged implements DomainEvent
{
    /**
     * Create the RBAC event.
     *
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public readonly string $entityType,
        public readonly string $entityId,
        public readonly string $operation,
        public readonly array $payload = [],
        public readonly int $schemaVersion = 1,
    ) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

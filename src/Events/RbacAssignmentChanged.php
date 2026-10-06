<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\AuthEventContext;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes every committed package-owned principal access assignment.
 *
 * @api
 */
final class RbacAssignmentChanged implements DomainEvent
{
    /**
     * Create the principal access assignment event.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $principalId,
        public readonly string $operation,
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $metadata = [],
        public readonly ?AuthEventContext $context = null,
        public readonly int $schemaVersion = 1,
    ) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

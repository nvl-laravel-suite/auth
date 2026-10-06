<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes the identifier of one committed Auth audit record.
 *
 * @api
 */
final class AuthAuditRecorded implements DomainEvent
{
    /**
     * Create an audit-recorded event.
     */
    public function __construct(public readonly string $auditId, public readonly int $schemaVersion = 1) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes one rejected package authentication with a stable reason code.
 *
 * @api
 */
final class AuthenticationRejected implements DomainEvent
{
    /**
     * Create an authentication-rejection event.
     */
    public function __construct(
        public readonly string $identifierName,
        public readonly string $identifier,
        public readonly string $reason,
        public readonly ?SubjectReference $subject = null,
        public readonly int $schemaVersion = 1,
    ) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

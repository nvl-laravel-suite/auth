<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes one package credential attempt without exposing the credential secret.
 *
 * @api
 */
final class AuthenticationAttempted implements DomainEvent
{
    /**
     * Create an authentication-attempt event.
     */
    public function __construct(
        public readonly string $identifierName,
        public readonly string $identifier,
        public readonly int $schemaVersion = 1,
    ) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes one successful package authentication.
 *
 * @api
 */
final class UserAuthenticated implements DomainEvent
{
    /**
     * Create an authentication event.
     */
    public function __construct(public readonly SubjectReference $subject, public readonly int $schemaVersion = 1) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

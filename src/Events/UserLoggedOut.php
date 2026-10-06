<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Publishes one completed Laravel guard logout.
 *
 * @api
 */
final class UserLoggedOut implements DomainEvent
{
    /**
     * Create a logout event.
     */
    public function __construct(public readonly ?SubjectReference $subject, public readonly int $schemaVersion = 1) {}

    /** Return the immutable event payload schema version. */
    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

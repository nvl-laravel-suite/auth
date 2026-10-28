<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/** Source-committed security fact for consumer notification listeners. @api */
final readonly class AccountSecurityChanged implements DomainEvent
{
    public function __construct(public SubjectReference $subject, public string $operation, public ?string $credentialId = null, public int $schemaVersion = 1) {}

    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

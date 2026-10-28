<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Carbon\CarbonImmutable;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/** Source-committed lifecycle facts; no browser capability or execution authority. @api */
final readonly class ImpersonationChanged implements DomainEvent
{
    public function __construct(public string $impersonationId, public SubjectReference $originalActor, public SubjectReference $effectiveSubject, public string $operation, public CarbonImmutable $expiresAt, public ?SubjectReference $operator = null, public int $schemaVersion = 1)
    {
        if (! in_array($operation, ['granted', 'stopped', 'expired', 'revoked'], true)) {
            throw new \InvalidArgumentException('Invalid impersonation lifecycle fact.');
        }
    }

    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

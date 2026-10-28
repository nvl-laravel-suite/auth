<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Nvl\Auth\Enums\RegistrationMethod;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Contracts\DomainEvent;

/**
 * Announces a source-committed native signup without credentials or host fields.
 *
 * @api
 */
final readonly class PrincipalRegistered implements DomainEvent
{
    public function __construct(public SubjectReference $subject, public RegistrationMethod $method, public string $classification = 'public', public int $schemaVersion = 1) {}

    public function schemaVersion(): int
    {
        return $this->schemaVersion;
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Captures Auth audit facts in a host-owned test store.
 */
final class HostAuditRecorder implements AuthAuditRecorder
{
    /**
     * @var list<array{action: string, outcome: string, subject: SubjectReference|null}>
     */
    public array $facts = [];

    /**
     * Capture one package audit fact without using package persistence.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function record(
        string $action,
        string $outcome = 'success',
        ?SubjectReference $subject = null,
        ?Authenticatable $actor = null,
        ?string $clientId = null,
        array $metadata = [],
    ): ?object {
        $this->facts[] = [
            'action' => $action,
            'outcome' => $outcome,
            'subject' => $subject,
        ];

        return null;
    }
}

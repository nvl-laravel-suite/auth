<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Persists transport-neutral Auth audit facts in a host-selected store.
 */
interface AuthAuditRecorder
{
    /**
     * Record one Auth audit fact and return the host record when available.
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
    ): ?object;
}

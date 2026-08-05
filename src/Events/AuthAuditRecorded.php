<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Publishes the identifier of one committed Auth audit record.
 */
final class AuthAuditRecorded implements ShouldDispatchAfterCommit
{
    use Dispatchable;

    /**
     * Create an audit-recorded event.
     */
    public function __construct(public readonly string $auditId) {}
}

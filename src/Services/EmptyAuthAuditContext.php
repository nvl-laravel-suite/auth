<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\AuthAuditContextProvider;

/**
 * Empty audit metadata until a host explicitly supplies its bounded context.
 *
 * @internal
 */
final readonly class EmptyAuthAuditContext implements AuthAuditContextProvider
{
    public function ipAddress(): ?string
    {
        return null;
    }

    public function userAgent(): ?string
    {
        return null;
    }

    public function requestId(): ?string
    {
        return null;
    }
}

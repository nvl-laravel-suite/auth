<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\AuthEventContext;

/** Refuses activity projection until a tenant-safe integration is configured. */
final readonly class DisabledTenantAwareAuthActivityBridge implements TenantAwareAuthActivityBridge
{
    public function record(string $action, AuthEventContext $context, array $metadata): void
    {
        throw AuthException::invalidConfiguration('The tenant-aware Auth activity bridge is disabled.');
    }
}

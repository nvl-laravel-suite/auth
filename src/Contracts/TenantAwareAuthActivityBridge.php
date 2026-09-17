<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\AuthEventContext;

/** Projects privacy-bounded Auth semantics into a tenant-safe activity implementation. */
interface TenantAwareAuthActivityBridge
{
    /** @param array<string, scalar|null> $metadata */
    public function record(string $action, AuthEventContext $context, array $metadata): void;
}

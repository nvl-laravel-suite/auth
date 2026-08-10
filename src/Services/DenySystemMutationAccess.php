<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Denies actorless mutations until the host explicitly supplies trust policy.
 */
final readonly class DenySystemMutationAccess implements SystemMutationAccess
{
    /**
     * Deny the requested system mutation.
     */
    public function allows(
        SystemMutationContext $context,
        string $ability,
        mixed $target = null,
    ): bool {
        return false;
    }
}

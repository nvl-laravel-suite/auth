<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Grants trusted system mutations in isolated package tests.
 */
final readonly class AllowAllSystemMutationAccess implements SystemMutationAccess
{
    /**
     * Grant the requested system mutation.
     */
    public function allows(
        SystemMutationContext $context,
        string $ability,
        mixed $target = null,
    ): bool {
        return true;
    }
}

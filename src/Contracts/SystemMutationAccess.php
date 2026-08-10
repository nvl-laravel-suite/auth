<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Authorizes explicitly actorless package mutations for trusted host workflows.
 */
interface SystemMutationAccess
{
    /**
     * Determine whether the system context may perform one package ability.
     */
    public function allows(
        SystemMutationContext $context,
        string $ability,
        mixed $target = null,
    ): bool;
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Revokes credentials and sessions when a principal lifecycle transition requires containment.
 */
interface PrincipalSessionContainment
{
    /**
     * Contain every package and host session for one principal.
     */
    public function contain(
        Authenticatable $principal,
        string $operation,
        ?SystemMutationContext $context = null,
    ): void;
}

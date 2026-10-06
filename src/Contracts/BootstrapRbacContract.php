<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Results\RbacSynchronizationResult;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the bootstrap rbac use-case boundary.
 *
 * @api
 */
interface BootstrapRbacContract
{
    /**
     * Synchronize all RBAC contributions through a trusted installation context.
     */
    public function execute(SystemMutationContext $context): RbacSynchronizationResult;
}

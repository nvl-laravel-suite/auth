<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\UserBulkOperation;
use Nvl\Auth\Results\BulkUserResult;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Defines the bulk update users use-case boundary.
 *
 * @api
 */
interface BulkUpdateUsersContract
{
    /**
     * Apply one operation to at most one hundred principals.
     *
     * @param  list<string>  $userIds
     */
    public function execute(
        Authenticatable|SystemMutationContext $authority,
        UserBulkOperation $operation,
        array $userIds,
    ): BulkUserResult;
}

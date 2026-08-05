<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\Enums\UserBulkOperation;

/**
 * Reports one bounded bulk principal mutation.
 */
final readonly class BulkUserResult
{
    /**
     * Create the bulk result.
     *
     * @param  list<string>  $userIds
     */
    public function __construct(
        public UserBulkOperation $operation,
        public array $userIds,
        public int $affected,
    ) {}
}

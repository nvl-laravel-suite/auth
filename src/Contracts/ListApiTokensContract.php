<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;

/**
 * Defines the list api tokens use-case boundary.
 *
 * @api
 */
interface ListApiTokensContract
{
    /**
     * Return subject-owned tokens.
     *
     * @return list<ApiTokenSnapshot>
     */
    public function execute(Authenticatable $subject): array;
}

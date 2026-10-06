<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Collection;
use Nvl\Auth\Models\User;

/**
 * Defines the suggest users use-case boundary.
 *
 * @api
 */
interface SuggestUsersContract
{
    /**
     * Find enabled principals by name or email.
     *
     * @return Collection<int, User>
     */
    public function execute(Authenticatable $actor, string $search, ?int $limit = null): Collection;
}

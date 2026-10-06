<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Defines the list role templates use-case boundary.
 *
 * @api
 */
interface ListRoleTemplatesContract
{
    /**
     * Return every validated template with presentation and hierarchy metadata.
     *
     * @return list<array<string, mixed>>
     */
    public function execute(Authenticatable $actor): array;
}

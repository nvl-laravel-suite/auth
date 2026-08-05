<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Resolves a login identifier through host authentication authority.
 */
interface AuthIdentifierResolver
{
    /**
     * Resolve one host subject without authenticating it.
     */
    public function resolve(string $identifierName, string $identifier): ?Authenticatable;
}

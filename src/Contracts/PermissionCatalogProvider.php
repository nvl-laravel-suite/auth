<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Contributes permission names to the package's Spatie catalog synchronization.
 */
interface PermissionCatalogProvider
{
    /**
     * Return stable permission names.
     *
     * @return list<string>
     */
    public function permissions(): array;
}

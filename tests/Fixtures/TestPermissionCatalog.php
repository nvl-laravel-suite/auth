<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\PermissionCatalogProvider;

/**
 * Contributes fixture permissions.
 */
final class TestPermissionCatalog implements PermissionCatalogProvider
{
    /**
     * Return fixture permission names.
     */
    public function permissions(): array
    {
        return ['users.view', 'users.manage'];
    }
}

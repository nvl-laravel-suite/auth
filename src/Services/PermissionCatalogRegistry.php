<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\PermissionCatalogProvider;

/**
 * Merges host permission catalogs deterministically.
 */
final readonly class PermissionCatalogRegistry
{
    /**
     * Create the permission registry.
     *
     * @param  iterable<PermissionCatalogProvider>  $providers
     */
    public function __construct(private iterable $providers) {}

    /**
     * Return unique sorted permission names.
     *
     * @return list<string>
     */
    public function permissions(): array
    {
        $permissions = [];

        foreach ($this->providers as $provider) {
            foreach ($provider->permissions() as $permission) {
                if (trim($permission) !== '') {
                    $permissions[trim($permission)] = true;
                }
            }
        }

        $names = array_keys($permissions);
        sort($names);

        return $names;
    }
}

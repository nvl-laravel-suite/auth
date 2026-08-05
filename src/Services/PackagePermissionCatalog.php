<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\PermissionCatalogProvider;

/**
 * Contributes every package-owned management ability to Spatie Permission.
 */
final readonly class PackagePermissionCatalog implements PermissionCatalogProvider
{
    /**
     * Create the package catalog provider.
     */
    public function __construct(private FeatureManifest $manifest) {}

    /** {@inheritDoc} */
    public function permissions(): array
    {
        $permissions = [];

        foreach ($this->manifest->definitions() as $definition) {
            foreach ($definition->managementAbilities as $ability) {
                $permissions[$ability] = true;
            }
        }

        $names = array_keys($permissions);
        sort($names);

        return $names;
    }
}

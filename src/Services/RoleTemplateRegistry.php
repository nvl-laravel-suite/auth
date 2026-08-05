<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\RoleTemplateProvider;

/**
 * Merges host role templates deterministically.
 */
final readonly class RoleTemplateRegistry
{
    /**
     * Create the role-template registry.
     *
     * @param  iterable<RoleTemplateProvider>  $providers
     */
    public function __construct(private iterable $providers) {}

    /**
     * Return merged role templates.
     *
     * @return array<string, list<string>>
     */
    public function roles(): array
    {
        $roles = [];

        foreach ($this->providers as $provider) {
            foreach ($provider->roles() as $role => $permissions) {
                if (trim($role) === '') {
                    continue;
                }

                $current = $roles[$role] ?? [];
                $roles[$role] = array_values(array_unique([
                    ...$current,
                    ...array_values(array_filter($permissions, static fn (string $permission): bool => trim($permission) !== '')),
                ]));
                sort($roles[$role]);
            }
        }

        ksort($roles);

        return $roles;
    }
}

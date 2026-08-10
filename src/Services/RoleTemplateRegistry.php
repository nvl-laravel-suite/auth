<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\RoleTemplate;

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
     * @return array<string, RoleTemplate>
     */
    public function roles(): array
    {
        $roles = [];

        foreach ($this->providers as $provider) {
            foreach ($provider->roles() as $template) {
                if (array_key_exists($template->key, $roles)) {
                    throw AuthException::invalidConfiguration(
                        "Role template keys must be unique; [{$template->key}] was contributed more than once.",
                    );
                }

                $roles[$template->key] = $template;
            }
        }

        ksort($roles);

        return $roles;
    }
}

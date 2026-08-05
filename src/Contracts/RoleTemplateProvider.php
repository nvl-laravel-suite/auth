<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

/**
 * Contributes guard-aware role templates backed by Spatie Permission.
 */
interface RoleTemplateProvider
{
    /**
     * Return role names mapped to their permission names.
     *
     * @return array<string, list<string>>
     */
    public function roles(): array;
}

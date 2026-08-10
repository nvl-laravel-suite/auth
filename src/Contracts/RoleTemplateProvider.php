<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\ValueObjects\RoleTemplate;

/**
 * Contributes guard-aware role templates backed by Spatie Permission.
 */
interface RoleTemplateProvider
{
    /**
     * Return validated role templates.
     *
     * @return list<RoleTemplate>
     */
    public function roles(): array;
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\RoleTemplateProvider;

/**
 * Contributes one fixture role template.
 */
final class TestRoleTemplates implements RoleTemplateProvider
{
    /**
     * Return fixture role templates.
     */
    public function roles(): array
    {
        return ['manager' => ['users.view', 'users.manage']];
    }
}

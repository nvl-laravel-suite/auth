<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\ValueObjects\RoleTemplate;

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
        return [
            new RoleTemplate(
                key: 'manager',
                permissions: ['users.view', 'users.manage'],
                displayName: 'Manager',
                description: 'Manages host users.',
                parentRole: 'manager-base',
                priority: 50,
                metadata: ['color' => 'blue'],
            ),
        ];
    }
}

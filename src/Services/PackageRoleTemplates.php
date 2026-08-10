<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\ValueObjects\RoleTemplate;

/**
 * Provides safe package role templates without auto-assigning any principal.
 */
final readonly class PackageRoleTemplates implements RoleTemplateProvider
{
    /**
     * Create the built-in role templates.
     */
    public function __construct(private PackagePermissionCatalog $catalog) {}

    /** {@inheritDoc} */
    public function roles(): array
    {
        $superAdmin = config('nvl-auth.features.rbac.settings.super_admin_role', 'super-admin');
        $superAdmin = is_string($superAdmin) && trim($superAdmin) !== '' ? trim($superAdmin) : 'super-admin';

        return [
            new RoleTemplate(
                key: $superAdmin,
                permissions: $this->catalog->permissions(),
                displayName: 'Super administrator',
                description: 'Unrestricted package administration role.',
                priority: 100_000,
            ),
            new RoleTemplate(
                key: 'auth-auditor',
                permissions: ['nvl-auth.audits.view', 'nvl-auth.audits.viewAny'],
                displayName: 'Auth auditor',
                description: 'Read-only access to authentication audit records.',
            ),
            new RoleTemplate(
                key: 'auth-user-manager',
                permissions: [
                    'nvl-auth.users.create',
                    'nvl-auth.users.delete',
                    'nvl-auth.users.restore',
                    'nvl-auth.users.update',
                    'nvl-auth.users.view',
                    'nvl-auth.users.viewAny',
                ],
                displayName: 'Auth user manager',
                description: 'Management access to package principals.',
            ),
        ];
    }
}

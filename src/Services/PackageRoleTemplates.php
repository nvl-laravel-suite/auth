<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Contracts\RoleTemplateProvider;

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
            $superAdmin => $this->catalog->permissions(),
            'auth-auditor' => [
                'nvl-auth.audits.view',
                'nvl-auth.audits.viewAny',
            ],
            'auth-user-manager' => [
                'nvl-auth.users.create',
                'nvl-auth.users.delete',
                'nvl-auth.users.restore',
                'nvl-auth.users.update',
                'nvl-auth.users.view',
                'nvl-auth.users.viewAny',
            ],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;

/**
 * Defines the closed mapping surface for host-owned management policies.
 */
final class AuthManagementAbilityCatalog
{
    /**
     * Return every supported management alias and its policy metadata.
     *
     * @return array<string, array{
     *     ability: string,
     *     feature: AuthFeature,
     *     operation: string,
     *     subject: 'none'|'optional'|'target',
     *     policy: string,
     *     default_model: class-string
     * }>
     */
    public function definitions(): array
    {
        return [
            'users.viewAny' => $this->definitionFor('nvl-auth.users.viewAny', AuthFeature::PrincipalManagement, 'viewAny', 'none', 'users', User::class),
            'users.view' => $this->definitionFor('nvl-auth.users.view', AuthFeature::PrincipalManagement, 'view', 'target', 'users', User::class),
            'users.create' => $this->definitionFor('nvl-auth.users.create', AuthFeature::PrincipalManagement, 'create', 'none', 'users', User::class),
            'users.update' => $this->definitionFor('nvl-auth.users.update', AuthFeature::PrincipalManagement, 'update', 'target', 'users', User::class),
            'users.delete' => $this->definitionFor('nvl-auth.users.delete', AuthFeature::PrincipalManagement, 'delete', 'target', 'users', User::class),
            'users.restore' => $this->definitionFor('nvl-auth.users.restore', AuthFeature::PrincipalManagement, 'restore', 'target', 'users', User::class),
            'users.manageAccess' => $this->definitionFor('nvl-auth.users.manageAccess', AuthFeature::PrincipalManagement, 'manageAccess', 'optional', 'users', User::class),
            'invitations.viewAny' => $this->definitionFor('nvl-auth.invitations.viewAny', AuthFeature::Invitations, 'viewAny', 'none', 'invitations', Invitation::class),
            'invitations.create' => $this->definitionFor('nvl-auth.invitations.create', AuthFeature::Invitations, 'create', 'none', 'invitations', Invitation::class),
            'invitations.resend' => $this->definitionFor('nvl-auth.invitations.resend', AuthFeature::Invitations, 'resend', 'target', 'invitations', Invitation::class),
            'invitations.revoke' => $this->definitionFor('nvl-auth.invitations.revoke', AuthFeature::Invitations, 'revoke', 'target', 'invitations', Invitation::class),
            'clients.viewAny' => $this->definitionFor('nvl-auth.clients.viewAny', AuthFeature::Clients, 'viewAny', 'none', 'clients', AuthClient::class),
            'clients.view' => $this->definitionFor('nvl-auth.clients.view', AuthFeature::Clients, 'view', 'target', 'clients', AuthClient::class),
            'clients.create' => $this->definitionFor('nvl-auth.clients.create', AuthFeature::Clients, 'create', 'none', 'clients', AuthClient::class),
            'clients.update' => $this->definitionFor('nvl-auth.clients.update', AuthFeature::Clients, 'update', 'target', 'clients', AuthClient::class),
            'clients.delete' => $this->definitionFor('nvl-auth.clients.delete', AuthFeature::Clients, 'delete', 'target', 'clients', AuthClient::class),
            'rbac.view' => $this->definitionFor('nvl-auth.rbac.view', AuthFeature::Rbac, 'viewRbac', 'none', 'roles', Role::class),
            'rbac.manageRoles' => $this->definitionFor('nvl-auth.rbac.manageRoles', AuthFeature::Rbac, 'manageRoles', 'none', 'roles', Role::class),
            'rbac.managePermissions' => $this->definitionFor('nvl-auth.rbac.managePermissions', AuthFeature::Rbac, 'managePermissions', 'none', 'permissions', Permission::class),
            'rbac.synchronize' => $this->definitionFor('nvl-auth.rbac.synchronize', AuthFeature::Rbac, 'synchronizeRbac', 'none', 'permissions', Permission::class),
            'audits.viewAny' => $this->definitionFor('nvl-auth.audits.viewAny', AuthFeature::Audit, 'viewAny', 'none', 'audits', AuthAudit::class),
            'audits.view' => $this->definitionFor('nvl-auth.audits.view', AuthFeature::Audit, 'view', 'target', 'audits', AuthAudit::class),
        ];
    }

    /**
     * Return one required alias definition.
     *
     * @return array{
     *     ability: string,
     *     feature: AuthFeature,
     *     operation: string,
     *     subject: 'none'|'optional'|'target',
     *     policy: string,
     *     default_model: class-string
     * }
     */
    public function definition(string $alias): array
    {
        return $this->definitions()[$alias]
            ?? throw AuthException::invalidConfiguration("Unknown Auth management alias [{$alias}].");
    }

    /**
     * Find a definition by package ability.
     *
     * @return array{
     *     alias: string,
     *     ability: string,
     *     feature: AuthFeature,
     *     operation: string,
     *     subject: 'none'|'optional'|'target',
     *     policy: string,
     *     default_model: class-string
     * }|null
     */
    public function forAbility(string $ability): ?array
    {
        foreach ($this->definitions() as $alias => $definition) {
            if ($definition['ability'] === $ability) {
                return ['alias' => $alias, ...$definition];
            }
        }

        return null;
    }

    /**
     * Return package abilities owned by one feature.
     *
     * @return list<string>
     */
    public function abilitiesFor(AuthFeature $feature): array
    {
        return array_values(array_map(
            static fn (array $definition): string => $definition['ability'],
            array_filter(
                $this->definitions(),
                static fn (array $definition): bool => $definition['feature'] === $feature,
            ),
        ));
    }

    /**
     * Create one normalized catalog definition.
     *
     * @param  'none'|'optional'|'target'  $subject
     * @param  class-string  $defaultModel
     * @return array{
     *     ability: string,
     *     feature: AuthFeature,
     *     operation: string,
     *     subject: 'none'|'optional'|'target',
     *     policy: string,
     *     default_model: class-string
     * }
     */
    private function definitionFor(
        string $ability,
        AuthFeature $feature,
        string $operation,
        string $subject,
        string $policy,
        string $defaultModel,
    ): array {
        return [
            'ability' => $ability,
            'feature' => $feature,
            'operation' => $operation,
            'subject' => $subject,
            'policy' => $policy,
            'default_model' => $defaultModel,
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\FeatureDefinition;

/**
 * Provides the closed, authoritative catalog of package capabilities.
 */
final class FeatureManifest
{
    /**
     * Return every feature definition keyed by feature value.
     *
     * @return array<string, FeatureDefinition>
     */
    public function definitions(): array
    {
        $all = [
            FeatureOperation::Read,
            FeatureOperation::Enroll,
            FeatureOperation::Issue,
            FeatureOperation::Use,
            FeatureOperation::Update,
            FeatureOperation::Revoke,
            FeatureOperation::Cleanup,
        ];
        $readWrite = [
            FeatureOperation::Read,
            FeatureOperation::Issue,
            FeatureOperation::Use,
            FeatureOperation::Update,
            FeatureOperation::Revoke,
            FeatureOperation::Cleanup,
        ];
        $definitions = [
            new FeatureDefinition(
                AuthFeature::Authentication,
                $readWrite,
                routeFamilies: ['public' => 'authentication', 'account' => 'authentication'],
                routeNames: ['public' => ['login'], 'account' => ['logout']],
                routeDependencies: ['public' => [AuthFeature::Password, AuthFeature::Sessions]],
            ),
            new FeatureDefinition(
                AuthFeature::PrincipalManagement,
                $all,
                routeFamilies: ['account' => 'profile', 'management' => 'users'],
                routeNames: [
                    'account' => ['profile.show', 'profile.update'],
                    'management' => [
                        'users.index',
                        'users.suggestions',
                        'users.bulk',
                        'users.store',
                        'users.show',
                        'users.update',
                        'users.status',
                        'users.roles',
                        'users.permissions',
                        'users.restore',
                        'users.destroy',
                    ],
                ],
                managementAbilities: [
                    'nvl-auth.users.viewAny',
                    'nvl-auth.users.view',
                    'nvl-auth.users.create',
                    'nvl-auth.users.update',
                    'nvl-auth.users.delete',
                    'nvl-auth.users.restore',
                    'nvl-auth.users.manageAccess',
                ],
            ),
            new FeatureDefinition(
                AuthFeature::Password,
                $readWrite,
                [AuthFeature::Authentication],
                ['public' => 'passwords', 'account' => 'passwords'],
                ['public' => ['password.request', 'password.reset'], 'account' => ['password.update', 'password.confirm']],
                ['account' => [AuthFeature::Sessions]],
            ),
            new FeatureDefinition(
                AuthFeature::EmailVerification,
                $readWrite,
                [AuthFeature::Authentication],
                ['public' => 'email_verification', 'account' => 'email_verification'],
                ['public' => ['email.verify'], 'account' => ['email.request']],
            ),
            new FeatureDefinition(
                AuthFeature::MagicLinks,
                $readWrite,
                [AuthFeature::Authentication],
                ['public' => 'magic_links'],
                ['public' => ['magic_links.request', 'magic_links.consume']],
                ['public' => [AuthFeature::Sessions]],
            ),
            new FeatureDefinition(
                AuthFeature::SecurityCodes,
                $readWrite,
                [AuthFeature::Authentication],
                ['public' => 'security_codes'],
                ['public' => ['security_codes.request', 'security_codes.verify']],
            ),
            new FeatureDefinition(
                AuthFeature::Invitations,
                $readWrite,
                routeFamilies: ['public' => 'invitations', 'management' => 'invitations'],
                routeNames: [
                    'public' => ['invitations.accept'],
                    'management' => ['invitations.index', 'invitations.store', 'invitations.resend', 'invitations.destroy'],
                ],
                managementAbilities: [
                    'nvl-auth.invitations.viewAny',
                    'nvl-auth.invitations.create',
                    'nvl-auth.invitations.resend',
                    'nvl-auth.invitations.revoke',
                ],
            ),
            new FeatureDefinition(
                AuthFeature::Totp,
                $all,
                [AuthFeature::Authentication],
                ['account' => 'totp'],
                ['account' => ['totp.enroll', 'totp.confirm', 'totp.verify', 'totp.revoke']],
            ),
            new FeatureDefinition(
                AuthFeature::Passkeys,
                $all,
                [AuthFeature::Authentication],
                ['public' => 'passkeys', 'account' => 'passkeys'],
                [
                    'public' => ['passkeys.authentication.options', 'passkeys.authentication.finish'],
                    'account' => ['passkeys.registration.options', 'passkeys.registration.finish', 'passkeys.revoke'],
                ],
                ['public' => [AuthFeature::Sessions]],
            ),
            new FeatureDefinition(
                AuthFeature::RecoveryCodes,
                $all,
                [AuthFeature::Authentication],
                ['account' => 'recovery_codes'],
                ['account' => ['recovery_codes.regenerate', 'recovery_codes.consume', 'recovery_codes.revoke']],
            ),
            new FeatureDefinition(
                AuthFeature::SocialIdentities,
                $all,
                [AuthFeature::Authentication],
                ['public' => 'social_identities', 'account' => 'social_identities'],
                [
                    'public' => ['social.redirect', 'social.callback'],
                    'account' => ['social.link', 'social.link.callback', 'social.destroy'],
                ],
                ['public' => [AuthFeature::Sessions]],
            ),
            new FeatureDefinition(
                AuthFeature::Clients,
                $readWrite,
                [AuthFeature::Authentication],
                routeFamilies: ['public' => 'clients', 'management' => 'clients'],
                routeNames: [
                    'public' => ['clients.start'],
                    'management' => ['clients.index', 'clients.store', 'clients.show', 'clients.update', 'clients.status', 'clients.destroy'],
                ],
                managementAbilities: [
                    'nvl-auth.clients.viewAny',
                    'nvl-auth.clients.view',
                    'nvl-auth.clients.create',
                    'nvl-auth.clients.update',
                    'nvl-auth.clients.delete',
                ],
            ),
            new FeatureDefinition(AuthFeature::Sessions, [FeatureOperation::Read, FeatureOperation::Use, FeatureOperation::Revoke], [AuthFeature::Authentication]),
            new FeatureDefinition(
                AuthFeature::ApiTokens,
                $readWrite,
                [AuthFeature::Authentication],
                ['account' => 'api_tokens'],
                ['account' => ['api_tokens.index', 'api_tokens.store', 'api_tokens.update', 'api_tokens.rotate', 'api_tokens.destroy', 'api_tokens.destroy_all']],
            ),
            new FeatureDefinition(
                AuthFeature::Rbac,
                $all,
                routeFamilies: ['management' => 'rbac'],
                routeNames: ['management' => [
                    'rbac.synchronize',
                    'roles.index',
                    'roles.hierarchy',
                    'roles.templates',
                    'roles.analytics',
                    'roles.apply_template',
                    'roles.store',
                    'roles.show',
                    'roles.update',
                    'roles.clone',
                    'roles.destroy',
                    'permissions.index',
                    'permissions.store',
                    'permissions.show',
                    'permissions.update',
                    'permissions.destroy',
                ]],
                managementAbilities: [
                    'nvl-auth.rbac.view',
                    'nvl-auth.rbac.manageRoles',
                    'nvl-auth.rbac.managePermissions',
                    'nvl-auth.rbac.synchronize',
                ],
            ),
            new FeatureDefinition(
                AuthFeature::Audit,
                [FeatureOperation::Read, FeatureOperation::Issue, FeatureOperation::Cleanup],
                routeFamilies: ['management' => 'audits'],
                routeNames: ['management' => ['audits.index', 'audits.show']],
                managementAbilities: ['nvl-auth.audits.viewAny', 'nvl-auth.audits.view'],
            ),
        ];

        return array_combine(
            array_map(static fn (FeatureDefinition $definition): string => $definition->feature->value, $definitions),
            $definitions,
        );
    }

    /**
     * Return one required feature definition.
     */
    public function definition(AuthFeature $feature): FeatureDefinition
    {
        return $this->definitions()[$feature->value]
            ?? throw AuthException::invalidConfiguration("Unknown Auth feature [{$feature->value}].");
    }
}

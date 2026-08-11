<?php

declare(strict_types=1);

namespace Nvl\Auth\Providers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Adapters\Laravel\EloquentAuthSubjectResolver;
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Adapters\Laravel\LaravelGuardIdentifierResolver;
use Nvl\Auth\Adapters\Laravel\LaravelPrincipalSessionContainment;
use Nvl\Auth\Adapters\Laravel\LaravelRequestAuditContextProvider;
use Nvl\Auth\Adapters\Passkeys\WebauthnPasskeyCeremony;
use Nvl\Auth\Console\Commands\AdoptPrincipalsCommand;
use Nvl\Auth\Console\Commands\AuthDoctorCommand;
use Nvl\Auth\Console\Commands\InstallAuthSchemaCommand;
use Nvl\Auth\Console\Commands\ListAuthFeaturesCommand;
use Nvl\Auth\Console\Commands\PruneAuthStateCommand;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PermissionCatalogProvider;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\ConfiguredApiTokenAbilityProvider;
use Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\EloquentPasswordUpdater;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Services\EloquentSuccessfulLoginMetadataRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\Services\LaravelGateAuthManagementAccess;
use Nvl\Auth\Services\PackageInvitationRegistrationMapper;
use Nvl\Auth\Services\PackageInvitationSubjectResolver;
use Nvl\Auth\Services\PasswordAccountConfirmation;
use Nvl\Auth\Services\PermissionCatalogRegistry;
use Nvl\Auth\Services\PrincipalEligibility;
use Nvl\Auth\Services\RoleTemplateRegistry;
use Nvl\Auth\Services\UnavailableSocialIdentityProvider;
use Nvl\Auth\Services\UnavailableSocialSubjectResolver;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Data\Services\TypeScriptSourceRegistry;

/**
 * Registers the passive package layer and lazy feature integrations.
 */
final class AuthServiceProvider extends ServiceProvider
{
    /**
     * Merge canonical configuration and bind package contracts.
     */
    public function register(): void
    {
        $this->mergeConfigurationRecursively();
        $this->app->register(DataServiceProvider::class);
        $this->configureOwnedIdentityStorage();
        $this->app->singleton(AuthConfiguration::class);
        $this->app->singleton(AuthModelRegistry::class);
        $this->app->singleton(AuthSchemaManager::class);
        $this->app->singleton(FeatureManifest::class);
        $this->app->singleton(FeatureGate::class);
        $this->app->singleton(BrowserSession::class, LaravelBrowserSession::class);
        $this->app->singleton(AuthAuditContextProvider::class, LaravelRequestAuditContextProvider::class);
        $this->bindConfiguredContract(
            AuthAuditRecorderContract::class,
            'features.audit.services.recorder',
            AuthAuditRecorder::class,
        );
        $this->app->singleton(AuthManagementAccess::class, LaravelGateAuthManagementAccess::class);
        $this->bindConfiguredContract(
            PasswordUpdater::class,
            'features.password.services.updater',
            EloquentPasswordUpdater::class,
        );
        $this->bindConfiguredContract(
            PrincipalAttributeMapper::class,
            'features.principal_management.services.attribute_mapper',
            ConfiguredPrincipalAttributeMapper::class,
        );
        $this->bindConfiguredContract(
            AccountConfirmation::class,
            'features.principal_management.services.account_confirmation',
            PasswordAccountConfirmation::class,
        );
        $this->bindConfiguredContract(
            PrincipalSessionContainment::class,
            'features.principal_management.services.session_containment',
            LaravelPrincipalSessionContainment::class,
        );
        $this->bindConfiguredContract(
            RbacPrincipalAccess::class,
            'features.rbac.services.principal_access',
            EloquentRbacPrincipalAccess::class,
        );
        $this->bindConfiguredContract(
            SystemMutationAccess::class,
            'services.system_mutation_access',
            DenySystemMutationAccess::class,
        );
        $this->bindConfiguredContract(
            AuthSubjectResolver::class,
            'features.authentication.services.subject_resolver',
            EloquentAuthSubjectResolver::class,
        );
        $this->bindConfiguredContract(
            AuthIdentifierResolver::class,
            'features.authentication.services.identifier_resolver',
            LaravelGuardIdentifierResolver::class,
        );
        $this->bindConfiguredContract(
            SuccessfulLoginMetadataRecorder::class,
            'features.authentication.services.login_metadata_recorder',
            EloquentSuccessfulLoginMetadataRecorder::class,
        );
        $this->bindConfiguredContract(
            AuthenticationEligibility::class,
            'features.authentication.services.eligibility',
            PrincipalEligibility::class,
        );
        $this->bindConfiguredContract(
            ApiTokenManager::class,
            'features.api_tokens.services.manager',
            SanctumApiTokenManager::class,
        );
        $this->bindConfiguredContract(
            ApiTokenAbilityProvider::class,
            'features.api_tokens.services.ability_provider',
            ConfiguredApiTokenAbilityProvider::class,
        );
        $this->bindConfiguredContract(
            SocialIdentityProvider::class,
            'features.social_identities.services.provider',
            UnavailableSocialIdentityProvider::class,
        );
        $this->bindConfiguredContract(
            SocialSubjectResolver::class,
            'features.social_identities.services.subject_resolver',
            UnavailableSocialSubjectResolver::class,
        );
        $this->bindConfiguredContract(
            PasskeyCeremony::class,
            'features.passkeys.services.ceremony',
            WebauthnPasskeyCeremony::class,
        );
        $this->bindConfiguredContract(
            InvitationSubjectResolver::class,
            'features.invitations.services.subject_resolver',
            PackageInvitationSubjectResolver::class,
        );
        $this->bindConfiguredContract(
            InvitationRegistrationMapper::class,
            'features.invitations.services.registration_mapper',
            PackageInvitationRegistrationMapper::class,
        );
        $this->registerExtensionRegistries();
        $this->app->register(RouteServiceProvider::class);
    }

    /**
     * Publish package resources and register operator commands.
     */
    public function boot(
        AuthConfiguration $configuration,
        TypeScriptSourceRegistry $typeScriptSources,
    ): void {
        $typeScriptSources->register(__DIR__.'/..', 'nvl/auth');
        $this->configureOwnedIdentityStorage();
        $root = dirname(__DIR__, 2);
        $this->publishes([$root.'/config/nvl-auth.php' => config_path('nvl-auth.php')], 'auth-config');
        $this->publishesMigrations([$root.'/database/migrations' => database_path('migrations')], 'auth-migrations');
        $this->publishes([$root.'/resources/boost/skills' => base_path('.agents/skills')], 'auth-skills');
        $this->publishes([
            $root.'/resources/adoption/principals.v1.example.json' => base_path('nvl-auth.principals.json'),
        ], 'auth-adoption');

        if ($configuration->boolean('migrations.enabled', true)
            && ($configuration->enabled() || $configuration->boolean('migrations.load_when_disabled', false))) {
            $this->loadMigrationsFrom($root.'/database/migrations');
        }

        if ($configuration->enabled() && $configuration->featureEnabled(AuthFeature::ApiTokens)) {
            $models = $this->app->make(AuthModelRegistry::class);
            Sanctum::usePersonalAccessTokenModel($models->personalAccessTokenClass());
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                AdoptPrincipalsCommand::class,
                AuthDoctorCommand::class,
                InstallAuthSchemaCommand::class,
                ListAuthFeaturesCommand::class,
                PruneAuthStateCommand::class,
            ]);
        }
    }

    /**
     * Recursively merge defaults so partial feature overrides remain complete.
     */
    private function mergeConfigurationRecursively(): void
    {
        $path = dirname(__DIR__, 2).'/config/nvl-auth.php';
        $defaults = require $path;
        $configuration = $this->app->make(ConfigRepository::class);
        $configured = $configuration->get('nvl-auth', []);

        if (! is_array($defaults) || ! is_array($configured)) {
            throw AuthException::invalidConfiguration('Auth configuration must be an array.');
        }

        $configuration->set('nvl-auth', array_replace_recursive($defaults, $configured));
    }

    /**
     * Wire Laravel authentication and Spatie Permission to package-owned models.
     */
    private function configureOwnedIdentityStorage(): void
    {
        $configuration = $this->app->make(ConfigRepository::class);

        if (! (bool) $configuration->get('nvl-auth.enabled', true)) {
            return;
        }

        if ((bool) $configuration->get('nvl-auth.features.principal_management.enabled', true)
            && (bool) $configuration->get('nvl-auth.features.principal_management.settings.use_as_auth_model', true)) {
            $guard = $configuration->get('nvl-auth.guard', 'web');
            $provider = is_string($guard)
                ? $configuration->get("auth.guards.{$guard}.provider")
                : null;
            $userModel = $configuration->get(
                'nvl-auth.features.principal_management.models.user',
                User::class,
            );

            if (is_string($provider) && trim($provider) !== '' && is_string($userModel)) {
                $configuration->set("auth.providers.{$provider}.model", $userModel);
            }

            $broker = (bool) $configuration->get('nvl-auth.features.password.enabled', true)
                ? $configuration->get('nvl-auth.password_broker')
                    ?? $configuration->get('auth.defaults.passwords')
                : null;

            if (is_string($broker) && trim($broker) !== '') {
                $configuration->set(
                    "auth.passwords.{$broker}.table",
                    $configuration->get('nvl-auth.tables.password_reset_tokens', AuthTables::PasswordResetTokens),
                );
                $connection = $configuration->get('nvl-auth.connection');

                if (is_string($connection) && trim($connection) !== '') {
                    $configuration->set("auth.passwords.{$broker}.connection", trim($connection));
                }
            }
        }

        if (! (bool) $configuration->get('nvl-auth.features.rbac.enabled', true)
            || ! (bool) $configuration->get('nvl-auth.features.rbac.settings.use_package_storage', true)) {
            return;
        }

        $configuration->set(
            'permission.models.role',
            $configuration->get('nvl-auth.features.rbac.models.role', Role::class),
        );
        $configuration->set(
            'permission.models.permission',
            $configuration->get('nvl-auth.features.rbac.models.permission', Permission::class),
        );
        $configuration->set('permission.table_names', [
            'roles' => $configuration->get('nvl-auth.tables.roles', AuthTables::Roles),
            'permissions' => $configuration->get('nvl-auth.tables.permissions', AuthTables::Permissions),
            'model_has_permissions' => $configuration->get('nvl-auth.tables.model_has_permissions', AuthTables::ModelHasPermissions),
            'model_has_roles' => $configuration->get('nvl-auth.tables.model_has_roles', AuthTables::ModelHasRoles),
            'role_has_permissions' => $configuration->get('nvl-auth.tables.role_has_permissions', AuthTables::RoleHasPermissions),
        ]);
        $columnNames = $configuration->get('permission.column_names', []);
        $columnNames = is_array($columnNames) ? $columnNames : [];
        $configuration->set('permission.column_names', array_replace($columnNames, [
            'role_pivot_key' => 'role_id',
            'permission_pivot_key' => 'permission_id',
            'model_morph_key' => 'model_id',
        ]));
        $configuration->set('permission.teams', false);
    }

    /**
     * Bind one optional integration through resolution-time validation.
     *
     * @param  class-string  $contract
     * @param  class-string|null  $fallback
     */
    private function bindConfiguredContract(
        string $contract,
        string $configurationPath,
        ?string $fallback,
    ): void {
        $this->app->singleton($contract, static function (Container $container) use (
            $configurationPath,
            $contract,
            $fallback,
        ): object {
            $implementation = config("nvl-auth.{$configurationPath}");
            $implementation = is_string($implementation) && trim($implementation) !== ''
                ? $implementation
                : $fallback;

            if (! is_string($implementation) || ! is_a($implementation, $contract, true)) {
                throw AuthException::invalidConfiguration(
                    "Auth configuration [{$configurationPath}] must implement [{$contract}].",
                );
            }

            $resolved = $container->make($implementation);

            if (! $resolved instanceof $contract) {
                throw AuthException::invalidConfiguration(
                    "Auth service [{$implementation}] did not resolve [{$contract}].",
                );
            }

            return $resolved;
        });
    }

    /**
     * Register lazy Spatie catalog and role-template extension registries.
     */
    private function registerExtensionRegistries(): void
    {
        $this->app->singleton(PermissionCatalogRegistry::class, function (Container $container): PermissionCatalogRegistry {
            return new PermissionCatalogRegistry($this->extensions(
                $container,
                'features.rbac.services.permission_catalogs',
                PermissionCatalogProvider::class,
            ));
        });
        $this->app->singleton(RoleTemplateRegistry::class, function (Container $container): RoleTemplateRegistry {
            return new RoleTemplateRegistry($this->extensions(
                $container,
                'features.rbac.services.role_templates',
                RoleTemplateProvider::class,
            ));
        });
    }

    /**
     * Resolve a configured extension list.
     *
     * @template TExtension of object
     *
     * @param  class-string<TExtension>  $contract
     * @return list<TExtension>
     */
    private function extensions(
        Container $container,
        string $configurationPath,
        string $contract,
    ): array {
        $configured = config("nvl-auth.{$configurationPath}", []);

        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration("Auth extensions [{$configurationPath}] must be an array.");
        }

        $extensions = [];

        foreach ($configured as $implementation) {
            if (! is_string($implementation) || ! is_a($implementation, $contract, true)) {
                throw AuthException::invalidConfiguration(
                    "Auth extension [{$configurationPath}] must contain implementations of [{$contract}].",
                );
            }

            $extension = $container->make($implementation);

            if (! $extension instanceof $contract) {
                throw AuthException::invalidConfiguration("Auth extension [{$implementation}] is invalid.");
            }

            $extensions[] = $extension;
        }

        return $extensions;
    }
}

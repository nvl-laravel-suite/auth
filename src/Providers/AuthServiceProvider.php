<?php

declare(strict_types=1);

namespace Nvl\Auth\Providers;

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Adapters\Laravel\DisabledTenantHttpResolver;
use Nvl\Auth\Adapters\Laravel\EloquentAuthSubjectResolver;
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Adapters\Laravel\LaravelGuardIdentifierResolver;
use Nvl\Auth\Adapters\Laravel\LaravelPrincipalSessionContainment;
use Nvl\Auth\Adapters\Laravel\LaravelRequestAuditContextProvider;
use Nvl\Auth\Adapters\Passkeys\WebauthnPasskeyCeremony;
use Nvl\Auth\Console\Commands\AdoptPrincipalsCommand;
use Nvl\Auth\Console\Commands\AuthConfigurationCommand;
use Nvl\Auth\Console\Commands\AuthConfigureCommand;
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
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
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
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\Middleware\EnsureAuthTenantAccess;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthAuditWriter;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Services\AuthManagementAbilityCatalog;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\AuthTenantContextParticipant;
use Nvl\Auth\Services\AuthTenantMembershipAccess;
use Nvl\Auth\Services\AuthTenantRbacQueries;
use Nvl\Auth\Services\CentralIdentityAuditRecorder;
use Nvl\Auth\Services\ConfiguredApiTokenAbilityProvider;
use Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\DisabledInvitationRecipientProof;
use Nvl\Auth\Services\DisabledTenantAwareAuthActivityBridge;
use Nvl\Auth\Services\EloquentMembershipPrincipalResolver;
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
use Nvl\Auth\Services\PermissionRegistrarReference;
use Nvl\Auth\Services\PermissionStorageReadiness;
use Nvl\Auth\Services\PrincipalEligibility;
use Nvl\Auth\Services\RbacPrincipalTracker;
use Nvl\Auth\Services\RoleTemplateRegistry;
use Nvl\Auth\Services\UnavailableSocialIdentityProvider;
use Nvl\Auth\Services\UnavailableSocialSubjectResolver;
use Nvl\Auth\Tenancy\AuthTenancyAdoption;
use Nvl\Data\Providers\DataServiceProvider;
use Nvl\Data\Services\TypeScriptSourceRegistry;
use Nvl\Support\Config\PackageOptions;
use Nvl\Support\Doctor\PackageDoctorContributor;
use Nvl\Support\Providers\TenantServiceProvider;
use Nvl\Support\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Support\Tenancy\Enums\TenantResourceKind;
use Nvl\Support\Tenancy\Services\TenantContextParticipants;
use Nvl\Support\Tenancy\Services\TenantResourceRegistry;
use Nvl\Support\Tenancy\ValueObjects\TenantResourceDefinition;
use Nvl\Support\Traits\MergesPackageConfiguration;
use Nvl\Support\Traits\RegistersNamespacedResources;
use Nvl\Tenancy\Services\TenantAdoptionRegistry;
use Spatie\Permission\PermissionRegistrar;

/**
 * Registers the passive package layer and lazy feature integrations.
 */
final class AuthServiceProvider extends ServiceProvider
{
    use MergesPackageConfiguration;
    use RegistersNamespacedResources;

    /**
     * Merge canonical configuration and bind package contracts.
     */
    public function register(): void
    {
        PackageDoctorContributor::register($this->app, 'nvl/auth', fn (): array => array_map(static fn (array $check): array => ['key' => $check['name'], ...$check], $this->app->make(AuthDoctor::class)->inspect()));

        $this->mergePackageConfiguration(dirname(__DIR__, 2).'/config/nvl-auth.php', 'nvl-auth');
        $this->app->register(DataServiceProvider::class);
        $this->app->register(TenantServiceProvider::class);
        $this->app->beforeResolving(TenantHttpResolver::class, static function (
            string $abstract,
            array $parameters,
            Container $container,
        ): void {
            if ($container->bound(TenantHttpResolver::class)) {
                return;
            }
            if ($container->make(ConfigRepository::class)->get('nvl-tenancy.enabled') === true) {
                throw AuthException::invalidConfiguration('A tenant HTTP resolver is required when tenancy is enabled.');
            }

            $container->bind(TenantHttpResolver::class, DisabledTenantHttpResolver::class);
        });
        $this->configureOwnedIdentityStorage();
        $this->app->singleton(AuthConfiguration::class);
        $this->app->singleton(AuthModelRegistry::class);
        $this->app->singleton(AuthManagementAbilityCatalog::class);
        $this->app->singleton(AuthSchemaManager::class);
        $this->app->singleton(FeatureManifest::class);
        $this->app->singleton(FeatureGate::class);
        $this->app->scoped(RbacPrincipalTracker::class);
        $this->app->scoped(AuthTenantContextParticipant::class);
        $this->app->scoped(AuthTenantRbacQueries::class);
        $this->app->make(TenantContextParticipants::class)->register(AuthTenantContextParticipant::class);
        $this->registerTenancyResources();
        $this->app->scoped(BrowserSession::class, LaravelBrowserSession::class);
        $this->app->scoped(TenantAuthenticationSession::class, LaravelBrowserSession::class);
        $this->app->singleton(TenantAwareAuthActivityBridge::class, function (Container $container): TenantAwareAuthActivityBridge {
            $bridge = config('nvl-auth.tenancy.activity_bridge', 'disabled');
            if ($bridge === 'disabled') {
                return new DisabledTenantAwareAuthActivityBridge;
            }
            if (! is_string($bridge) || ! is_a($bridge, TenantAwareAuthActivityBridge::class, true)) {
                throw AuthException::invalidConfiguration(
                    'The Auth activity bridge must implement the tenant-aware bridge contract.',
                );
            }

            $resolved = $container->make($bridge);
            if (! $resolved instanceof TenantAwareAuthActivityBridge) {
                throw AuthException::invalidConfiguration(
                    'The Auth activity bridge container binding must resolve the tenant-aware bridge contract.',
                );
            }

            return $resolved;
        });
        $this->app->singleton(InvitationRecipientProof::class, function (Container $container): InvitationRecipientProof {
            $proof = config('nvl-auth.tenancy.recipient_proof', 'disabled');
            if ($proof === 'disabled') {
                return new DisabledInvitationRecipientProof;
            }
            if (! is_string($proof) || ! is_a($proof, InvitationRecipientProof::class, true)) {
                throw AuthException::invalidConfiguration(
                    'The Auth invitation recipient proof must be disabled or implement the recipient proof contract.',
                );
            }

            $resolved = $container->make($proof);
            if (! $resolved instanceof InvitationRecipientProof) {
                throw AuthException::invalidConfiguration(
                    'The Auth invitation recipient proof binding must resolve the recipient proof contract.',
                );
            }

            return $resolved;
        });
        $this->app->scoped(AuthAuditContextProvider::class, LaravelRequestAuditContextProvider::class);
        $this->app->scoped(AuthAuditRecorder::class);
        $this->app->scoped(AuthAuditWriter::class);
        $this->app->scoped(CentralIdentityAuditRecorder::class);
        $this->bindConfiguredContract(
            AuthAuditRecorderContract::class,
            'features.audit.services.recorder',
            AuthAuditRecorder::class,
            scoped: true,
        );
        $this->bindConfiguredContract(
            AuthManagementAccess::class,
            'services.management_access',
            LaravelGateAuthManagementAccess::class,
        );
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
        $this->bindConfiguredContract(
            MembershipPrincipalResolver::class,
            'features.memberships.services.principal_resolver',
            EloquentMembershipPrincipalResolver::class,
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
        if (config('nvl-tenancy.enabled') === true && $configuration->featureEnabled(AuthFeature::Memberships)) {
            $this->app->scoped(TenantMembershipAccess::class, AuthTenantMembershipAccess::class);
            $kernel = $this->app->make(HttpKernelContract::class);
            $kernel->addToMiddlewarePriorityAfter(AuthenticatesRequests::class, EnsureAuthTenantAccess::class);
        }
        if (config('nvl-tenancy.enabled') === true && $configuration->featureEnabled(AuthFeature::Rbac)) {
            $principal = $this->app->make(AuthModelRegistry::class)->rbacPrincipalClass();
            $principal::retrieved(fn (Model $model) => $this->app->make(RbacPrincipalTracker::class)->track($model));
            $principal::created(fn (Model $model) => $this->app->make(RbacPrincipalTracker::class)->track($model));
        }
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
                AuthConfigurationCommand::class,
                AuthConfigureCommand::class,
                AuthDoctorCommand::class,
                InstallAuthSchemaCommand::class,
                ListAuthFeaturesCommand::class,
                PruneAuthStateCommand::class,
            ]);
        }
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

        if ($configuration->get('nvl-auth.adoption.principal_model.enabled') === true) {
            $guard = $configuration->get('nvl-auth.adoption.principal_model.guard');
            $provider = $configuration->get('nvl-auth.adoption.principal_model.provider');
            if (! is_string($guard) || trim($guard) === ''
                || ! is_string($provider) || trim($provider) === ''
                || $configuration->get("auth.guards.{$guard}.provider") !== $provider
                || ! is_array($configuration->get("auth.providers.{$provider}"))) {
                throw AuthException::invalidConfiguration('Principal model adoption requires an explicit guard and provider that match the host configuration.');
            }
            $userModel = $configuration->get(
                'nvl-auth.features.principal_management.models.user',
                User::class,
            );

            if (! is_string($userModel) || ! is_a($userModel, Model::class, true)) {
                throw AuthException::invalidConfiguration('Principal adoption requires an Eloquent user model.');
            }
            $configuration->set("auth.providers.{$provider}.model", $userModel);
        }

        if ($configuration->get('nvl-auth.adoption.password_broker.enabled') === true) {
            $broker = $configuration->get('nvl-auth.adoption.password_broker.broker');
            if (! is_string($broker) || trim($broker) === ''
                || ! is_array($configuration->get("auth.passwords.{$broker}"))) {
                throw AuthException::invalidConfiguration('Password storage adoption requires an explicit configured broker.');
            }
            $configuration->set(
                "auth.passwords.{$broker}.table",
                AuthTables::get(AuthTables::PasswordResetTokens),
            );
            $configuration->set("auth.passwords.{$broker}.connection", PackageOptions::connection('auth'));
        }

        if ($configuration->get('nvl-auth.adoption.spatie_storage.enabled') !== true) {
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
            'roles' => $configuration->get('nvl-auth.tables.roles', AuthTables::get(AuthTables::Roles)),
            'permissions' => $configuration->get('nvl-auth.tables.permissions', AuthTables::get(AuthTables::Permissions)),
            'model_has_permissions' => $configuration->get('nvl-auth.tables.model_has_permissions', AuthTables::get(AuthTables::ModelHasPermissions)),
            'model_has_roles' => $configuration->get('nvl-auth.tables.model_has_roles', AuthTables::get(AuthTables::ModelHasRoles)),
            'role_has_permissions' => $configuration->get('nvl-auth.tables.role_has_permissions', AuthTables::get(AuthTables::RoleHasPermissions)),
        ]);
        $columnNames = $configuration->get('permission.column_names', []);
        $columnNames = is_array($columnNames) ? $columnNames : [];
        $configuration->set('permission.column_names', array_replace($columnNames, [
            'role_pivot_key' => 'role_id',
            'permission_pivot_key' => 'permission_id',
            'model_morph_key' => 'model_id',
            'team_foreign_key' => 'tenant_id',
        ]));
        $this->registerPermissionReadiness();
    }

    /** Register one lazy hook without retaining scoped readiness in a singleton. */
    private function registerPermissionReadiness(): void
    {
        if ($this->app->bound('nvl.auth.permission-readiness-hook')) {
            return;
        }
        $this->app->instance('nvl.auth.permission-readiness-hook', true);
        $this->app->scoped(PermissionStorageReadiness::class);
        $this->app->forgetInstance(PermissionRegistrar::class);
        $registrarReference = new PermissionRegistrarReference;
        $this->app->beforeResolving(PermissionRegistrar::class, function () use ($registrarReference): void {
            $teams = $this->app->make(PermissionStorageReadiness::class)->initialize();
            $registrar = $registrarReference->current();
            if ($registrar instanceof PermissionRegistrar) {
                $registrar->teams = $teams;
                $registrar->teamsKey = 'tenant_id';
            }
        });
        $this->app->afterResolving(PermissionRegistrar::class, static function (PermissionRegistrar $registrar) use ($registrarReference): void {
            $registrarReference->remember($registrar);
        });
    }

    /** Register Auth's immutable tenant resource inventory without touching storage. */
    private function registerTenancyResources(): void
    {
        $resources = $this->app->make(TenantResourceRegistry::class);
        $models = $this->app->make(AuthModelRegistry::class);
        foreach ([
            new TenantResourceDefinition('auth.memberships', 'auth.memberships', TenantMembership::class),
            new TenantResourceDefinition('auth.membership_locks', 'auth.memberships', TenantMembershipLock::class),
            new TenantResourceDefinition('auth.roles', 'auth.rbac', $models->roleClass()),
            new TenantResourceDefinition('auth.invitations', 'auth.invitations', Invitation::class, allowsPlatformRows: true),
            new TenantResourceDefinition('auth.tokens', 'auth.tokens', $models->personalAccessTokenClass(), allowsPlatformRows: true),
            new TenantResourceDefinition('auth.challenges', 'auth.challenges', Challenge::class, allowsPlatformRows: true),
            new TenantResourceDefinition('auth.audits', 'auth.audits', AuthAudit::class, allowsPlatformRows: true),
            new TenantResourceDefinition('auth.authentication_intents', 'auth.authentication_intents', TenantAuthenticationIntent::class),
            new TenantResourceDefinition('auth.permissions', 'auth.permissions', $models->permissionClass(), TenantResourceKind::Platform),
        ] as $resource) {
            $resources->register($resource);
        }
        $this->app->booted(function (): void {
            if ($this->app->bound(TenantAdoptionRegistry::class)) {
                $this->app->make(TenantAdoptionRegistry::class)->register('auth', AuthTenancyAdoption::class);
            }
        });
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
        bool $scoped = false,
    ): void {
        $factory = static function (Container $container) use (
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
        };

        if ($scoped) {
            $this->app->scoped($contract, $factory);
        } else {
            $this->app->singleton($contract, $factory);
        }
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

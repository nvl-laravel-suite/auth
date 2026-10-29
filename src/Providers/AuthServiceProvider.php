<?php

declare(strict_types=1);

namespace Nvl\Auth\Providers;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Cookie\QueueingFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;
use Nvl\Auth\Adapters\ApiTokens\SanctumApiTokenManager;
use Nvl\Auth\Adapters\Laravel\EloquentAuthSubjectResolver;
use Nvl\Auth\Adapters\Laravel\LaravelGuardIdentifierResolver;
use Nvl\Auth\Adapters\Laravel\LaravelPrincipalSessionContainment;
use Nvl\Auth\Adapters\Laravel\ManagedSessionGuard;
use Nvl\Auth\Adapters\Passkeys\WebauthnPasskeyCeremony;
use Nvl\Auth\Console\Commands\AdoptEmailIdentitiesCommand;
use Nvl\Auth\Console\Commands\AdoptPrincipalsCommand;
use Nvl\Auth\Console\Commands\AuthConfigurationCommand;
use Nvl\Auth\Console\Commands\AuthConfigureCommand;
use Nvl\Auth\Console\Commands\AuthDoctorCommand;
use Nvl\Auth\Console\Commands\InstallAuthSchemaCommand;
use Nvl\Auth\Console\Commands\ListAuthFeaturesCommand;
use Nvl\Auth\Console\Commands\PruneAuthStateCommand;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordPolicy;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PermissionCatalogProvider;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\RegistrationAdmission;
use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Ownership\AuthAdoptionAdapter;
use Nvl\Auth\Ownership\AuthResourceRegistrar;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthAuditWriter;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthExecutionContext;
use Nvl\Auth\Services\AuthManagementAbilityCatalog;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\AuthOwnerContextParticipant;
use Nvl\Auth\Services\AuthOwnershipState;
use Nvl\Auth\Services\AuthRememberCredentials;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\CentralIdentityAuditRecorder;
use Nvl\Auth\Services\ConfiguredApiTokenAbilityProvider;
use Nvl\Auth\Services\ConfiguredPasswordPolicy;
use Nvl\Auth\Services\ConfiguredPrincipalAttributeMapper;
use Nvl\Auth\Services\ConfiguredRegistrationAdmission;
use Nvl\Auth\Services\DenyImpersonationAccess;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\DisabledInvitationRecipientProof;
use Nvl\Auth\Services\EloquentMembershipPrincipalResolver;
use Nvl\Auth\Services\EloquentPasswordUpdater;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Services\EloquentSuccessfulLoginMetadataRecorder;
use Nvl\Auth\Services\EmptyAuthAuditContext;
use Nvl\Auth\Services\EnrolledFactorAssurancePolicy;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\Services\LaravelGateAuthManagementAccess;
use Nvl\Auth\Services\PackageInvitationRegistrationMapper;
use Nvl\Auth\Services\PackageInvitationSubjectResolver;
use Nvl\Auth\Services\PasswordAccountConfirmation;
use Nvl\Auth\Services\PermissionCatalogRegistry;
use Nvl\Auth\Services\PermissionRegistrarReference;
use Nvl\Auth\Services\PermissionStorageReadiness;
use Nvl\Auth\Services\PrincipalCreationGuard;
use Nvl\Auth\Services\PrincipalEligibility;
use Nvl\Auth\Services\RbacPrincipalTracker;
use Nvl\Auth\Services\RejectPrincipalExtensions;
use Nvl\Auth\Services\RoleTemplateRegistry;
use Nvl\Auth\Services\UnavailableSocialIdentityProviderFactory;
use Nvl\Auth\Services\UsableAccountAuthenticationPolicy;
use Nvl\Ownership\Services\OwnershipAdoptionRegistry;
use Nvl\Support\Doctor\PackageDoctorContributor;
use Nvl\Support\Globals\GlobalNames;
use Nvl\Support\Ownership\Contracts\OwnershipIntegratedProvider;
use Nvl\Support\Ownership\Services\OwnershipContextParticipants;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use Nvl\Support\Traits\MergesPackageConfiguration;
use Nvl\Support\Traits\RegistersNamespacedResources;
use Spatie\Permission\PermissionRegistrar;
use Symfony\Component\HttpFoundation\Request;

/**
 * Registers the passive package layer and lazy feature integrations.
 */
final class AuthServiceProvider extends ServiceProvider implements OwnershipIntegratedProvider
{
    use MergesPackageConfiguration;
    use RegistersNamespacedResources;

    /**
     * Merge canonical configuration and bind package contracts.
     */
    public function register(): void
    {
        $this->callAfterResolving('auth', function (AuthManager $auth): void {
            $factory = $this->createManagedGuard(...);
            $auth->extend('nvl-managed-session', function ($app, string $name, array $config) use ($factory): ManagedSessionGuard {
                return $factory($name, $config);
            });
        });
        PackageDoctorContributor::register($this->app, 'nvl/auth', fn (): array => array_map(static fn (array $check): array => ['key' => $check['name'], ...$check], $this->app->make(AuthDoctor::class)->inspect()));
        $this->mergePackageConfiguration(dirname(__DIR__, 2).'/config/nvl-auth.php', 'nvl-auth');
        $this->configureOwnedIdentityStorage();
        $this->app->singleton(AuthConfiguration::class);
        $this->app->singleton(AuthModelRegistry::class);
        $this->app->singleton(AuthManagementAbilityCatalog::class);
        $this->app->singleton(AuthSchemaManager::class);
        $this->app->singleton(FeatureManifest::class);
        $this->app->scoped(FeatureGate::class);
        $this->app->scoped(AuthExecutionContext::class);
        $this->app->scoped(PrincipalCreationGuard::class);
        $this->app->scoped(AuthOwnershipState::class);
        $this->app->scoped(RbacPrincipalTracker::class);
        $this->app->scoped(AuthOwnerContextParticipant::class);
        $this->app->booted(function (): void {
            if (config('nvl-auth.ownership.scoped') === true) {
                $this->app->make(OwnershipContextParticipants::class)->register(AuthOwnerContextParticipant::class);
            }
            $this->app->make(AuthResourceRegistrar::class)->register($this->app->make(OwnershipResourceRegistry::class));
            if ($this->app->bound(OwnershipAdoptionRegistry::class)) {
                $this->app->make(OwnershipAdoptionRegistry::class)->register('auth', AuthAdoptionAdapter::class);
            }
        });
        $this->app->singletonIf(InvitationRecipientProof::class, function (Container $container): InvitationRecipientProof {
            $proof = config('nvl-auth.features.invitations.services.recipient_proof', 'disabled');
            if ($proof === 'disabled') {
                return new DisabledInvitationRecipientProof;
            }
            if (! is_string($proof) || ! is_a($proof, InvitationRecipientProof::class, true)) {
                throw AuthException::invalidConfiguration('The Auth invitation recipient proof must be disabled or implement the recipient proof contract.');
            }
            $resolved = $container->make($proof);
            if (! $resolved instanceof InvitationRecipientProof) {
                throw AuthException::invalidConfiguration('The Auth invitation recipient proof binding must resolve the recipient proof contract.');
            }

            return $resolved;
        });
        $this->app->scopedIf(AuthAuditContextProvider::class, EmptyAuthAuditContext::class);
        $this->app->scoped(AuthAuditRecorder::class);
        $this->app->scoped(AuthAuditWriter::class);
        $this->app->scoped(CentralIdentityAuditRecorder::class);
        $this->bindConfiguredContract(AuthAuditRecorderContract::class, 'features.audit.services.recorder', AuthAuditRecorder::class, scoped: true);
        $this->bindConfiguredContract(AuthManagementAccess::class, 'services.management_access', LaravelGateAuthManagementAccess::class);
        $this->bindConfiguredContract(PasswordPolicy::class, 'features.password.services.policy', ConfiguredPasswordPolicy::class);
        $this->bindConfiguredContract(PasswordUpdater::class, 'features.password.services.updater', EloquentPasswordUpdater::class);
        $this->bindConfiguredContract(RegistrationAdmission::class, 'features.registration.services.admission', ConfiguredRegistrationAdmission::class);
        $this->bindConfiguredContract(PrincipalExtensionMapper::class, 'features.principal_management.services.extension_mapper', RejectPrincipalExtensions::class);
        $this->bindConfiguredContract(PrincipalAttributeMapper::class, 'features.principal_management.services.attribute_mapper', ConfiguredPrincipalAttributeMapper::class);
        $this->bindConfiguredContract(AccountAuthenticationPolicy::class, 'features.principal_management.services.authentication_policy', UsableAccountAuthenticationPolicy::class);
        $this->bindConfiguredContract(ImpersonationAccess::class, 'features.impersonation.services.access', DenyImpersonationAccess::class, scoped: true);
        $this->bindConfiguredContract(AccountConfirmation::class, 'features.principal_management.services.account_confirmation', PasswordAccountConfirmation::class);
        $this->bindConfiguredContract(PrincipalSessionContainment::class, 'features.principal_management.services.session_containment', LaravelPrincipalSessionContainment::class);
        $this->bindConfiguredContract(RbacPrincipalAccess::class, 'features.rbac.services.principal_access', EloquentRbacPrincipalAccess::class);
        $this->bindConfiguredContract(SystemMutationAccess::class, 'services.system_mutation_access', DenySystemMutationAccess::class);
        $this->bindConfiguredContract(AuthSubjectResolver::class, 'features.authentication.services.subject_resolver', EloquentAuthSubjectResolver::class);
        $this->bindConfiguredContract(AuthIdentifierResolver::class, 'features.authentication.services.identifier_resolver', LaravelGuardIdentifierResolver::class);
        $this->bindConfiguredContract(SuccessfulLoginMetadataRecorder::class, 'features.authentication.services.login_metadata_recorder', EloquentSuccessfulLoginMetadataRecorder::class);
        $this->bindConfiguredContract(AuthenticationAssurancePolicy::class, 'features.authentication.services.assurance', EnrolledFactorAssurancePolicy::class);
        $this->bindConfiguredContract(AuthenticationEligibility::class, 'features.authentication.services.eligibility', PrincipalEligibility::class);
        $this->bindConfiguredContract(ApiTokenManager::class, 'features.api_tokens.services.manager', SanctumApiTokenManager::class);
        $this->bindConfiguredContract(ApiTokenAbilityProvider::class, 'features.api_tokens.services.ability_provider', ConfiguredApiTokenAbilityProvider::class);
        $this->bindConfiguredContract(SocialIdentityProviderFactory::class, 'features.social_identities.services.provider_factory', UnavailableSocialIdentityProviderFactory::class, scoped: true);
        $this->bindConfiguredContract(PasskeyCeremony::class, 'features.passkeys.services.ceremony', WebauthnPasskeyCeremony::class);
        $this->bindConfiguredContract(InvitationSubjectResolver::class, 'features.invitations.services.subject_resolver', PackageInvitationSubjectResolver::class);
        $this->bindConfiguredContract(InvitationRegistrationMapper::class, 'features.invitations.services.registration_mapper', PackageInvitationRegistrationMapper::class);
        $this->bindConfiguredContract(MembershipPrincipalResolver::class, 'features.memberships.services.principal_resolver', EloquentMembershipPrincipalResolver::class);
        $this->registerExtensionRegistries();
    }

    /**
     * Publish package resources and register operator commands.
     */
    public function boot(AuthConfiguration $configuration): void
    {
        $this->app->make(GlobalNames::class)->translations('auth', __DIR__.'/../../lang', $this->app->make('translation.loader'));
        $this->publishes([__DIR__.'/../../lang' => lang_path('vendor/nvl-auth')], 'nvl-auth-translations');
        if (config('nvl-auth.ownership.scoped') === true && $configuration->featureEnabled(AuthFeature::Rbac)) {
            $principal = $this->app->make(AuthModelRegistry::class)->rbacPrincipalClass();
            $principal::retrieved(fn (Model $model) => $this->app->make(RbacPrincipalTracker::class)->track($model));
            $principal::created(fn (Model $model) => $this->app->make(RbacPrincipalTracker::class)->track($model));
        }
        $this->configureOwnedIdentityStorage();
        $root = dirname(__DIR__, 2);
        $this->publishes([$root.'/config/nvl-auth.php' => config_path('nvl-auth.php')], 'nvl-auth-config');
        $this->publishesMigrations([$root.'/database/migrations' => database_path('migrations')], 'nvl-auth-migrations');
        $this->publishes([$root.'/resources/boost/skills' => base_path('.agents/skills')], 'nvl-auth-skills');
        $this->publishes([$root.'/resources/adoption/principals.v1.example.json' => base_path('nvl-auth.principals.json')], 'nvl-auth-adoption');
        if ($configuration->boolean('migrations.enabled', true) && ($configuration->enabled() || $configuration->boolean('migrations.load_when_disabled', false))) {
            $this->loadMigrationsFrom($root.'/database/migrations');
        }
        if ($configuration->enabled() && $configuration->featureEnabled(AuthFeature::ApiTokens)) {
            if (! class_exists(Sanctum::class)) {
                throw AuthException::invalidConfiguration('API tokens require laravel/sanctum.');
            }
            $models = $this->app->make(AuthModelRegistry::class);
            Sanctum::usePersonalAccessTokenModel($models->personalAccessTokenClass());
        }
        if ($this->app->runningInConsole()) {
            $this->commands([AdoptEmailIdentitiesCommand::class, AdoptPrincipalsCommand::class, AuthConfigurationCommand::class, AuthConfigureCommand::class, AuthDoctorCommand::class, InstallAuthSchemaCommand::class, ListAuthFeaturesCommand::class, PruneAuthStateCommand::class]);
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
        if ($configuration->get('nvl-auth.adoption.spatie_storage.enabled') !== true) {
            return;
        }
        $configuration->set('permission.models.role', $configuration->get('nvl-auth.features.rbac.models.role', Role::class));
        $configuration->set('permission.models.permission', $configuration->get('nvl-auth.features.rbac.models.permission', Permission::class));
        $configuration->set('permission.table_names', ['roles' => $configuration->get('nvl-auth.tables.roles', AuthTables::get(AuthTables::Roles)), 'permissions' => $configuration->get('nvl-auth.tables.permissions', AuthTables::get(AuthTables::Permissions)), 'model_has_permissions' => $configuration->get('nvl-auth.tables.model_has_permissions', AuthTables::get(AuthTables::ModelHasPermissions)), 'model_has_roles' => $configuration->get('nvl-auth.tables.model_has_roles', AuthTables::get(AuthTables::ModelHasRoles)), 'role_has_permissions' => $configuration->get('nvl-auth.tables.role_has_permissions', AuthTables::get(AuthTables::RoleHasPermissions))]);
        $columnNames = $configuration->get('permission.column_names', []);
        $columnNames = is_array($columnNames) ? $columnNames : [];
        $configuration->set('permission.column_names', array_replace($columnNames, ['role_pivot_key' => 'role_id', 'permission_pivot_key' => 'permission_id', 'model_morph_key' => 'model_id', 'team_foreign_key' => config('nvl-auth.ownership.scoped') === true ? 'owner_scope_key' : (config('permission.column_names.team_foreign_key') ?? 'team_id')]));
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
            // Spatie constructs the registrar while wiring the Gate during provider boot.
            if (! $this->app->isBooted()) {
                return;
            }
            $teams = $this->app->make(PermissionStorageReadiness::class)->initialize();
            $registrar = $registrarReference->current();
            if ($registrar instanceof PermissionRegistrar) {
                $registrar->teams = $teams;
                $teamKey = config('nvl-auth.ownership.scoped') === true ? 'owner_scope_key' : (config('permission.column_names.team_foreign_key') ?? 'team_id');
                if (! is_string($teamKey) || $teamKey === '') {
                    throw AuthException::invalidConfiguration('Permission team column must be a non-empty string.');
                }
                $registrar->teamsKey = $teamKey;
            }
        });
        $this->app->afterResolving(PermissionRegistrar::class, static function (PermissionRegistrar $registrar) use ($registrarReference): void {
            $registrarReference->remember($registrar);
        });
    }

    /**
     * Bind one optional integration through resolution-time validation.
     *
     * @param  class-string  $contract
     * @param  class-string|null  $fallback
     */
    private function bindConfiguredContract(string $contract, string $configurationPath, ?string $fallback, bool $scoped = false): void
    {
        $factory = static function (Container $container) use ($configurationPath, $contract, $fallback): object {
            $implementation = config("nvl-auth.{$configurationPath}");
            $implementation = is_string($implementation) && trim($implementation) !== '' ? $implementation : $fallback;
            if (! is_string($implementation) || ! is_a($implementation, $contract, true)) {
                throw AuthException::invalidConfiguration("Auth configuration [{$configurationPath}] must implement [{$contract}].");
            }
            $resolved = $container->make($implementation);
            if (! $resolved instanceof $contract) {
                throw AuthException::invalidConfiguration("Auth service [{$implementation}] did not resolve [{$contract}].");
            }

            return $resolved;
        };
        if ($scoped) {
            $this->app->scopedIf($contract, $factory);
        } else {
            $this->app->singletonIf($contract, $factory);
        }
    }

    /**
     * Register lazy Spatie catalog and role-template extension registries.
     */
    private function registerExtensionRegistries(): void
    {
        $this->app->singleton(PermissionCatalogRegistry::class, function (Container $container): PermissionCatalogRegistry {
            return new PermissionCatalogRegistry($this->extensions($container, 'features.rbac.services.permission_catalogs', PermissionCatalogProvider::class));
        });
        $this->app->singleton(RoleTemplateRegistry::class, function (Container $container): RoleTemplateRegistry {
            return new RoleTemplateRegistry($this->extensions($container, 'features.rbac.services.role_templates', RoleTemplateProvider::class));
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
    private function extensions(Container $container, string $configurationPath, string $contract): array
    {
        $configured = config("nvl-auth.{$configurationPath}", []);
        if (! is_array($configured)) {
            throw AuthException::invalidConfiguration("Auth extensions [{$configurationPath}] must be an array.");
        }
        $extensions = [];
        foreach ($configured as $implementation) {
            if (! is_string($implementation) || ! is_a($implementation, $contract, true)) {
                throw AuthException::invalidConfiguration("Auth extension [{$configurationPath}] must contain implementations of [{$contract}].");
            }
            $extension = $container->make($implementation);
            if (! $extension instanceof $contract) {
                throw AuthException::invalidConfiguration("Auth extension [{$implementation}] is invalid.");
            }
            $extensions[] = $extension;
        }

        return $extensions;
    }

    /** @param array<array-key, mixed> $config */
    private function createManagedGuard(string $name, array $config): ManagedSessionGuard
    {
        if (config('nvl-auth.features.managed_sessions.enabled') !== true || ! is_string($config['provider'] ?? null)) {
            throw AuthException::invalidConfiguration('The managed guard requires managed sessions and an explicit provider.');
        }
        $auth = $this->app->make(AuthManager::class);
        $provider = $auth->createUserProvider($config['provider']);
        $session = $this->app->make('session.store');
        $key = config('app.key');
        if ($provider === null || ! is_string($key)) {
            throw AuthException::invalidConfiguration('Invalid managed guard dependencies.');
        }
        $guard = new ManagedSessionGuard($name, $provider, $session, hashKey: $key);
        $guard->configureNative($this->app->make(AuthRememberCredentials::class), $this->app->make(AuthenticationSessions::class));
        $guard->setCookieJar($this->app->make(QueueingFactory::class));
        $guard->setDispatcher($this->app->make(Dispatcher::class));
        $request = $this->app->refresh('request', $guard, 'setRequest');
        if (! $request instanceof Request) {
            throw AuthException::invalidConfiguration('The managed guard requires a current request.');
        }
        $guard->setRequest($request);

        return $guard;
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Providers;

use Closure;
use Illuminate\Container\Container as LaravelContainer;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;
use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\ListApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RevokeAllApiTokensAction;
use Nvl\Auth\Actions\ApiTokens\RevokeApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\RotateApiTokenAction;
use Nvl\Auth\Actions\ApiTokens\UpdateApiTokenAction;
use Nvl\Auth\Actions\Audit\ListAuthAuditsAction;
use Nvl\Auth\Actions\Audit\ShowAuthAuditAction;
use Nvl\Auth\Actions\Authentication\CompletePendingTenantAuthenticationIntentAction;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Authentication\LogoutAction;
use Nvl\Auth\Actions\Authentication\RequestEmailVerificationAction;
use Nvl\Auth\Actions\Authentication\VerifyEmailAction;
use Nvl\Auth\Actions\Challenges\ConsumeMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAuthenticationAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAuthenticationAction;
use Nvl\Auth\Actions\Challenges\VerifySecurityCodeAction;
use Nvl\Auth\Actions\Challenges\VerifySecurityCodeAuthenticationAction;
use Nvl\Auth\Actions\Clients\CreateAuthClientAction;
use Nvl\Auth\Actions\Clients\DeleteAuthClientAction;
use Nvl\Auth\Actions\Clients\EndAuthClientSessionAction;
use Nvl\Auth\Actions\Clients\ListAuthClientsAction;
use Nvl\Auth\Actions\Clients\RecordAuthClientSessionAction;
use Nvl\Auth\Actions\Clients\SetAuthClientActiveAction;
use Nvl\Auth\Actions\Clients\ShowAuthClientAction;
use Nvl\Auth\Actions\Clients\StartAuthClientAction;
use Nvl\Auth\Actions\Clients\TouchAuthClientSessionAction;
use Nvl\Auth\Actions\Clients\UpdateAuthClientAction;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Invitations\FindActiveInvitationAction;
use Nvl\Auth\Actions\Invitations\ListInvitationProjectionsAction;
use Nvl\Auth\Actions\Invitations\ListInvitationsAction;
use Nvl\Auth\Actions\Invitations\PreviewInvitationAction;
use Nvl\Auth\Actions\Invitations\RecordInvitationDeliveryOutcomeAction;
use Nvl\Auth\Actions\Invitations\RegisterInvitationAction;
use Nvl\Auth\Actions\Invitations\ResendInvitationAction;
use Nvl\Auth\Actions\Invitations\RevokeInvitationAction;
use Nvl\Auth\Actions\Memberships\EnrollMembershipAction;
use Nvl\Auth\Actions\Memberships\ListMembershipsAction;
use Nvl\Auth\Actions\Memberships\ListOwnMembershipsAction;
use Nvl\Auth\Actions\Memberships\ProvisionTenantOwnerAction;
use Nvl\Auth\Actions\Memberships\RevokeMembershipAction;
use Nvl\Auth\Actions\Memberships\SetMembershipStatusAction;
use Nvl\Auth\Actions\Memberships\ShowMembershipAction;
use Nvl\Auth\Actions\Memberships\TransferMembershipOwnershipAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\RevokePasskeyAction;
use Nvl\Auth\Actions\Passwords\ConfirmPasswordAction;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Passwords\ResetPasswordAction;
use Nvl\Auth\Actions\Passwords\UpdatePasswordAction;
use Nvl\Auth\Actions\Rbac\AddRolePermissionsAction;
use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\BootstrapRbacAction;
use Nvl\Auth\Actions\Rbac\CheckRoleNameAvailabilityAction;
use Nvl\Auth\Actions\Rbac\CloneRoleAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionWithRolesAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\DeletePermissionAction;
use Nvl\Auth\Actions\Rbac\DeleteRoleAction;
use Nvl\Auth\Actions\Rbac\ListPermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\ListPermissionGroupsAction;
use Nvl\Auth\Actions\Rbac\ListPermissionOptionsAction;
use Nvl\Auth\Actions\Rbac\ListPermissionsAction;
use Nvl\Auth\Actions\Rbac\ListRoleCatalogAction;
use Nvl\Auth\Actions\Rbac\ListRoleHierarchyAction;
use Nvl\Auth\Actions\Rbac\ListRoleOptionsAction;
use Nvl\Auth\Actions\Rbac\ListRolesAction;
use Nvl\Auth\Actions\Rbac\ListRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\ResolvePermissionIdentifiersAction;
use Nvl\Auth\Actions\Rbac\ResolveRoleIdentifiersAction;
use Nvl\Auth\Actions\Rbac\ShowPermissionAction;
use Nvl\Auth\Actions\Rbac\ShowRbacAnalyticsAction;
use Nvl\Auth\Actions\Rbac\ShowRoleAction;
use Nvl\Auth\Actions\Rbac\ShowRoleAnalyticsAction;
use Nvl\Auth\Actions\Rbac\SuggestPermissionsAction;
use Nvl\Auth\Actions\Rbac\SuggestRolesAction;
use Nvl\Auth\Actions\Rbac\SynchronizePermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRbacAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\SyncRolePermissionsAction;
use Nvl\Auth\Actions\Rbac\UpdatePermissionAction;
use Nvl\Auth\Actions\Rbac\UpdateRoleAction;
use Nvl\Auth\Actions\RecoveryCodes\ConsumeRecoveryCodeAction;
use Nvl\Auth\Actions\RecoveryCodes\RegenerateRecoveryCodesAction;
use Nvl\Auth\Actions\RecoveryCodes\RevokeRecoveryCodesAction;
use Nvl\Auth\Actions\SocialIdentities\CompleteSocialAuthorizationAction;
use Nvl\Auth\Actions\SocialIdentities\LinkSocialIdentityAction;
use Nvl\Auth\Actions\SocialIdentities\RevokeSocialIdentityAction;
use Nvl\Auth\Actions\SocialIdentities\StartSocialAuthorizationAction;
use Nvl\Auth\Actions\Totp\ConfirmTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\RevokeTotpCredentialAction;
use Nvl\Auth\Actions\Totp\StartTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\VerifyTotpAction;
use Nvl\Auth\Actions\Users\BulkUpdateUsersAction;
use Nvl\Auth\Actions\Users\CreateUserAction;
use Nvl\Auth\Actions\Users\DeleteOwnAccountAction;
use Nvl\Auth\Actions\Users\DeleteUserAction;
use Nvl\Auth\Actions\Users\ListUsersAction;
use Nvl\Auth\Actions\Users\RestoreUserAction;
use Nvl\Auth\Actions\Users\SetUserActiveAction;
use Nvl\Auth\Actions\Users\ShowProfileAction;
use Nvl\Auth\Actions\Users\ShowUserAction;
use Nvl\Auth\Actions\Users\SuggestUsersAction;
use Nvl\Auth\Actions\Users\SyncUserPermissionsAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Actions\Users\UpdateProfileAction;
use Nvl\Auth\Actions\Users\UpdateUserAction;
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
use Nvl\Auth\Contracts\AcceptInvitationContract;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\AddRolePermissionsContract;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\ApplyRoleTemplateContract;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder as AuthAuditRecorderContract;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthIdentifierResolver;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\BeginPasskeyAuthenticationContract;
use Nvl\Auth\Contracts\BeginPasskeyRegistrationContract;
use Nvl\Auth\Contracts\BootstrapRbacContract;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\BulkUpdateUsersContract;
use Nvl\Auth\Contracts\CheckRoleNameAvailabilityContract;
use Nvl\Auth\Contracts\CloneRoleContract;
use Nvl\Auth\Contracts\CompletePendingTenantAuthenticationIntentContract;
use Nvl\Auth\Contracts\CompleteSocialAuthorizationContract;
use Nvl\Auth\Contracts\ConfirmPasswordContract;
use Nvl\Auth\Contracts\ConfirmTotpEnrollmentContract;
use Nvl\Auth\Contracts\ConsumeMagicLinkContract;
use Nvl\Auth\Contracts\ConsumeRecoveryCodeContract;
use Nvl\Auth\Contracts\CreateApiTokenContract;
use Nvl\Auth\Contracts\CreateAuthClientContract;
use Nvl\Auth\Contracts\CreateInvitationContract;
use Nvl\Auth\Contracts\CreatePermissionContract;
use Nvl\Auth\Contracts\CreatePermissionWithRolesContract;
use Nvl\Auth\Contracts\CreateRoleContract;
use Nvl\Auth\Contracts\CreateUserContract;
use Nvl\Auth\Contracts\DeleteAuthClientContract;
use Nvl\Auth\Contracts\DeleteOwnAccountContract;
use Nvl\Auth\Contracts\DeletePermissionContract;
use Nvl\Auth\Contracts\DeleteRoleContract;
use Nvl\Auth\Contracts\DeleteUserContract;
use Nvl\Auth\Contracts\EndAuthClientSessionContract;
use Nvl\Auth\Contracts\EnrollMembershipContract;
use Nvl\Auth\Contracts\EstablishAuthenticatedSessionContract;
use Nvl\Auth\Contracts\FindActiveInvitationContract;
use Nvl\Auth\Contracts\FinishPasskeyAuthenticationContract;
use Nvl\Auth\Contracts\FinishPasskeyRegistrationContract;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\InvitationRegistrationMapper;
use Nvl\Auth\Contracts\InvitationSubjectResolver;
use Nvl\Auth\Contracts\LinkSocialIdentityContract;
use Nvl\Auth\Contracts\ListApiTokensContract;
use Nvl\Auth\Contracts\ListAuthAuditsContract;
use Nvl\Auth\Contracts\ListAuthClientsContract;
use Nvl\Auth\Contracts\ListInvitationProjectionsContract;
use Nvl\Auth\Contracts\ListInvitationsContract;
use Nvl\Auth\Contracts\ListMembershipsContract;
use Nvl\Auth\Contracts\ListOwnMembershipsContract;
use Nvl\Auth\Contracts\ListPermissionCatalogContract;
use Nvl\Auth\Contracts\ListPermissionGroupsContract;
use Nvl\Auth\Contracts\ListPermissionOptionsContract;
use Nvl\Auth\Contracts\ListPermissionsContract;
use Nvl\Auth\Contracts\ListRoleCatalogContract;
use Nvl\Auth\Contracts\ListRoleHierarchyContract;
use Nvl\Auth\Contracts\ListRoleOptionsContract;
use Nvl\Auth\Contracts\ListRolesContract;
use Nvl\Auth\Contracts\ListRoleTemplatesContract;
use Nvl\Auth\Contracts\ListUsersContract;
use Nvl\Auth\Contracts\LoginContract;
use Nvl\Auth\Contracts\LogoutContract;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PermissionCatalogProvider;
use Nvl\Auth\Contracts\PreviewInvitationContract;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Contracts\ProvisionTenantOwnerContract;
use Nvl\Auth\Contracts\RbacPrincipalAccess;
use Nvl\Auth\Contracts\RecordAuthClientSessionContract;
use Nvl\Auth\Contracts\RecordInvitationDeliveryOutcomeContract;
use Nvl\Auth\Contracts\RegenerateRecoveryCodesContract;
use Nvl\Auth\Contracts\RegisterInvitationContract;
use Nvl\Auth\Contracts\RequestEmailVerificationContract;
use Nvl\Auth\Contracts\RequestMagicLinkAuthenticationContract;
use Nvl\Auth\Contracts\RequestMagicLinkContract;
use Nvl\Auth\Contracts\RequestPasswordResetContract;
use Nvl\Auth\Contracts\RequestSecurityCodeAuthenticationContract;
use Nvl\Auth\Contracts\RequestSecurityCodeContract;
use Nvl\Auth\Contracts\ResendInvitationContract;
use Nvl\Auth\Contracts\ResetPasswordContract;
use Nvl\Auth\Contracts\ResolvePermissionIdentifiersContract;
use Nvl\Auth\Contracts\ResolveRoleIdentifiersContract;
use Nvl\Auth\Contracts\RestoreUserContract;
use Nvl\Auth\Contracts\RevokeAllApiTokensContract;
use Nvl\Auth\Contracts\RevokeApiTokenContract;
use Nvl\Auth\Contracts\RevokeInvitationContract;
use Nvl\Auth\Contracts\RevokeMembershipContract;
use Nvl\Auth\Contracts\RevokePasskeyContract;
use Nvl\Auth\Contracts\RevokeRecoveryCodesContract;
use Nvl\Auth\Contracts\RevokeSocialIdentityContract;
use Nvl\Auth\Contracts\RevokeTotpCredentialContract;
use Nvl\Auth\Contracts\RoleTemplateProvider;
use Nvl\Auth\Contracts\RotateApiTokenContract;
use Nvl\Auth\Contracts\SetAuthClientActiveContract;
use Nvl\Auth\Contracts\SetMembershipStatusContract;
use Nvl\Auth\Contracts\SetUserActiveContract;
use Nvl\Auth\Contracts\ShowAuthAuditContract;
use Nvl\Auth\Contracts\ShowAuthClientContract;
use Nvl\Auth\Contracts\ShowMembershipContract;
use Nvl\Auth\Contracts\ShowPermissionContract;
use Nvl\Auth\Contracts\ShowProfileContract;
use Nvl\Auth\Contracts\ShowRbacAnalyticsContract;
use Nvl\Auth\Contracts\ShowRoleAnalyticsContract;
use Nvl\Auth\Contracts\ShowRoleContract;
use Nvl\Auth\Contracts\ShowUserContract;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Contracts\StartAuthClientContract;
use Nvl\Auth\Contracts\StartSocialAuthorizationContract;
use Nvl\Auth\Contracts\StartTotpEnrollmentContract;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Contracts\SuggestPermissionsContract;
use Nvl\Auth\Contracts\SuggestRolesContract;
use Nvl\Auth\Contracts\SuggestUsersContract;
use Nvl\Auth\Contracts\SynchronizePermissionCatalogContract;
use Nvl\Auth\Contracts\SynchronizeRbacContract;
use Nvl\Auth\Contracts\SynchronizeRoleTemplatesContract;
use Nvl\Auth\Contracts\SyncRolePermissionsContract;
use Nvl\Auth\Contracts\SyncUserPermissionsContract;
use Nvl\Auth\Contracts\SyncUserRolesContract;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\Contracts\TouchAuthClientSessionContract;
use Nvl\Auth\Contracts\TransferMembershipOwnershipContract;
use Nvl\Auth\Contracts\UpdateApiTokenContract;
use Nvl\Auth\Contracts\UpdateAuthClientContract;
use Nvl\Auth\Contracts\UpdatePasswordContract;
use Nvl\Auth\Contracts\UpdatePermissionContract;
use Nvl\Auth\Contracts\UpdateProfileContract;
use Nvl\Auth\Contracts\UpdateRoleContract;
use Nvl\Auth\Contracts\UpdateUserContract;
use Nvl\Auth\Contracts\VerifyEmailContract;
use Nvl\Auth\Contracts\VerifySecurityCodeAuthenticationContract;
use Nvl\Auth\Contracts\VerifySecurityCodeContract;
use Nvl\Auth\Contracts\VerifyTotpContract;
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
use Nvl\Support\Globals\GlobalNames;
use Nvl\Support\Providers\TenantServiceProvider;
use Nvl\Support\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Support\Tenancy\Enums\TenantResourceKind;
use Nvl\Support\Tenancy\Services\DisabledTenantMembershipAccess;
use Nvl\Support\Tenancy\Services\TenantContextParticipants;
use Nvl\Support\Tenancy\Services\TenantResourceRegistry;
use Nvl\Support\Tenancy\ValueObjects\TenantResourceDefinition;
use Nvl\Support\Traits\MergesPackageConfiguration;
use Nvl\Support\Traits\RegistersNamespacedResources;
use Nvl\Tenancy\Services\TenantAdoptionRegistry;
use ReflectionFunction;
use ReflectionMethod;
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
        $this->app->scopedIf(BrowserSession::class, LaravelBrowserSession::class);
        $this->app->scopedIf(TenantAuthenticationSession::class, LaravelBrowserSession::class);
        $this->app->singletonIf(TenantAwareAuthActivityBridge::class, function (Container $container): TenantAwareAuthActivityBridge {
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
        $this->app->singletonIf(InvitationRecipientProof::class, function (Container $container): InvitationRecipientProof {
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
        $this->app->scopedIf(AuthAuditContextProvider::class, LaravelRequestAuditContextProvider::class);
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
        $this->registerConsumerContracts();
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
        $this->app->make(GlobalNames::class)->translations('auth', __DIR__.'/../../lang', $this->app->make('translation.loader'));
        $this->publishes([
            __DIR__.'/../../lang' => lang_path('vendor/nvl-auth'),
        ], 'nvl-auth-translations');
        if (config('nvl-tenancy.enabled') === true && $configuration->featureEnabled(AuthFeature::Memberships)) {
            $this->registerMembershipAccess();
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
            // Spatie constructs the registrar while wiring the Gate during provider boot.
            if (! $this->app->isBooted()) {
                return;
            }
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
            $this->app->scopedIf($contract, $factory);
        } else {
            $this->app->singletonIf($contract, $factory);
        }
    }

    /** Register transient application-facing workflows without replacing host bindings. */
    private function registerConsumerContracts(): void
    {
        foreach ([
            CreateApiTokenContract::class => CreateApiTokenAction::class,
            ListApiTokensContract::class => ListApiTokensAction::class,
            RevokeAllApiTokensContract::class => RevokeAllApiTokensAction::class,
            RevokeApiTokenContract::class => RevokeApiTokenAction::class,
            RotateApiTokenContract::class => RotateApiTokenAction::class,
            UpdateApiTokenContract::class => UpdateApiTokenAction::class,
            ListAuthAuditsContract::class => ListAuthAuditsAction::class,
            ShowAuthAuditContract::class => ShowAuthAuditAction::class,
            CompletePendingTenantAuthenticationIntentContract::class => CompletePendingTenantAuthenticationIntentAction::class,
            EstablishAuthenticatedSessionContract::class => EstablishAuthenticatedSessionAction::class,
            LoginContract::class => LoginAction::class,
            LogoutContract::class => LogoutAction::class,
            RequestEmailVerificationContract::class => RequestEmailVerificationAction::class,
            VerifyEmailContract::class => VerifyEmailAction::class,
            ConsumeMagicLinkContract::class => ConsumeMagicLinkAction::class,
            RequestMagicLinkContract::class => RequestMagicLinkAction::class,
            RequestMagicLinkAuthenticationContract::class => RequestMagicLinkAuthenticationAction::class,
            RequestSecurityCodeContract::class => RequestSecurityCodeAction::class,
            RequestSecurityCodeAuthenticationContract::class => RequestSecurityCodeAuthenticationAction::class,
            VerifySecurityCodeContract::class => VerifySecurityCodeAction::class,
            VerifySecurityCodeAuthenticationContract::class => VerifySecurityCodeAuthenticationAction::class,
            CreateAuthClientContract::class => CreateAuthClientAction::class,
            DeleteAuthClientContract::class => DeleteAuthClientAction::class,
            EndAuthClientSessionContract::class => EndAuthClientSessionAction::class,
            ListAuthClientsContract::class => ListAuthClientsAction::class,
            RecordAuthClientSessionContract::class => RecordAuthClientSessionAction::class,
            SetAuthClientActiveContract::class => SetAuthClientActiveAction::class,
            ShowAuthClientContract::class => ShowAuthClientAction::class,
            StartAuthClientContract::class => StartAuthClientAction::class,
            TouchAuthClientSessionContract::class => TouchAuthClientSessionAction::class,
            UpdateAuthClientContract::class => UpdateAuthClientAction::class,
            AcceptInvitationContract::class => AcceptInvitationAction::class,
            CreateInvitationContract::class => CreateInvitationAction::class,
            FindActiveInvitationContract::class => FindActiveInvitationAction::class,
            ListInvitationProjectionsContract::class => ListInvitationProjectionsAction::class,
            ListInvitationsContract::class => ListInvitationsAction::class,
            PreviewInvitationContract::class => PreviewInvitationAction::class,
            RecordInvitationDeliveryOutcomeContract::class => RecordInvitationDeliveryOutcomeAction::class,
            RegisterInvitationContract::class => RegisterInvitationAction::class,
            ResendInvitationContract::class => ResendInvitationAction::class,
            RevokeInvitationContract::class => RevokeInvitationAction::class,
            EnrollMembershipContract::class => EnrollMembershipAction::class,
            ListMembershipsContract::class => ListMembershipsAction::class,
            ListOwnMembershipsContract::class => ListOwnMembershipsAction::class,
            ProvisionTenantOwnerContract::class => ProvisionTenantOwnerAction::class,
            RevokeMembershipContract::class => RevokeMembershipAction::class,
            SetMembershipStatusContract::class => SetMembershipStatusAction::class,
            ShowMembershipContract::class => ShowMembershipAction::class,
            TransferMembershipOwnershipContract::class => TransferMembershipOwnershipAction::class,
            BeginPasskeyAuthenticationContract::class => BeginPasskeyAuthenticationAction::class,
            BeginPasskeyRegistrationContract::class => BeginPasskeyRegistrationAction::class,
            FinishPasskeyAuthenticationContract::class => FinishPasskeyAuthenticationAction::class,
            FinishPasskeyRegistrationContract::class => FinishPasskeyRegistrationAction::class,
            RevokePasskeyContract::class => RevokePasskeyAction::class,
            ConfirmPasswordContract::class => ConfirmPasswordAction::class,
            RequestPasswordResetContract::class => RequestPasswordResetAction::class,
            ResetPasswordContract::class => ResetPasswordAction::class,
            UpdatePasswordContract::class => UpdatePasswordAction::class,
            AddRolePermissionsContract::class => AddRolePermissionsAction::class,
            ApplyRoleTemplateContract::class => ApplyRoleTemplateAction::class,
            BootstrapRbacContract::class => BootstrapRbacAction::class,
            CheckRoleNameAvailabilityContract::class => CheckRoleNameAvailabilityAction::class,
            CloneRoleContract::class => CloneRoleAction::class,
            CreatePermissionContract::class => CreatePermissionAction::class,
            CreatePermissionWithRolesContract::class => CreatePermissionWithRolesAction::class,
            CreateRoleContract::class => CreateRoleAction::class,
            DeletePermissionContract::class => DeletePermissionAction::class,
            DeleteRoleContract::class => DeleteRoleAction::class,
            ListPermissionCatalogContract::class => ListPermissionCatalogAction::class,
            ListPermissionGroupsContract::class => ListPermissionGroupsAction::class,
            ListPermissionOptionsContract::class => ListPermissionOptionsAction::class,
            ListPermissionsContract::class => ListPermissionsAction::class,
            ListRoleCatalogContract::class => ListRoleCatalogAction::class,
            ListRoleHierarchyContract::class => ListRoleHierarchyAction::class,
            ListRoleOptionsContract::class => ListRoleOptionsAction::class,
            ListRoleTemplatesContract::class => ListRoleTemplatesAction::class,
            ListRolesContract::class => ListRolesAction::class,
            ResolvePermissionIdentifiersContract::class => ResolvePermissionIdentifiersAction::class,
            ResolveRoleIdentifiersContract::class => ResolveRoleIdentifiersAction::class,
            ShowPermissionContract::class => ShowPermissionAction::class,
            ShowRbacAnalyticsContract::class => ShowRbacAnalyticsAction::class,
            ShowRoleContract::class => ShowRoleAction::class,
            ShowRoleAnalyticsContract::class => ShowRoleAnalyticsAction::class,
            SuggestPermissionsContract::class => SuggestPermissionsAction::class,
            SuggestRolesContract::class => SuggestRolesAction::class,
            SyncRolePermissionsContract::class => SyncRolePermissionsAction::class,
            SynchronizePermissionCatalogContract::class => SynchronizePermissionCatalogAction::class,
            SynchronizeRbacContract::class => SynchronizeRbacAction::class,
            SynchronizeRoleTemplatesContract::class => SynchronizeRoleTemplatesAction::class,
            UpdatePermissionContract::class => UpdatePermissionAction::class,
            UpdateRoleContract::class => UpdateRoleAction::class,
            ConsumeRecoveryCodeContract::class => ConsumeRecoveryCodeAction::class,
            RegenerateRecoveryCodesContract::class => RegenerateRecoveryCodesAction::class,
            RevokeRecoveryCodesContract::class => RevokeRecoveryCodesAction::class,
            CompleteSocialAuthorizationContract::class => CompleteSocialAuthorizationAction::class,
            LinkSocialIdentityContract::class => LinkSocialIdentityAction::class,
            RevokeSocialIdentityContract::class => RevokeSocialIdentityAction::class,
            StartSocialAuthorizationContract::class => StartSocialAuthorizationAction::class,
            ConfirmTotpEnrollmentContract::class => ConfirmTotpEnrollmentAction::class,
            RevokeTotpCredentialContract::class => RevokeTotpCredentialAction::class,
            StartTotpEnrollmentContract::class => StartTotpEnrollmentAction::class,
            VerifyTotpContract::class => VerifyTotpAction::class,
            BulkUpdateUsersContract::class => BulkUpdateUsersAction::class,
            CreateUserContract::class => CreateUserAction::class,
            DeleteOwnAccountContract::class => DeleteOwnAccountAction::class,
            DeleteUserContract::class => DeleteUserAction::class,
            ListUsersContract::class => ListUsersAction::class,
            RestoreUserContract::class => RestoreUserAction::class,
            SetUserActiveContract::class => SetUserActiveAction::class,
            ShowProfileContract::class => ShowProfileAction::class,
            ShowUserContract::class => ShowUserAction::class,
            SuggestUsersContract::class => SuggestUsersAction::class,
            SyncUserPermissionsContract::class => SyncUserPermissionsAction::class,
            SyncUserRolesContract::class => SyncUserRolesAction::class,
            UpdateProfileContract::class => UpdateProfileAction::class,
            UpdateUserContract::class => UpdateUserAction::class,
        ] as $contract => $implementation) {
            $this->app->bindIf($contract, $implementation);
        }
    }

    /** Preserve host membership adapters while upgrading only Core's native transient fallback. */
    private function registerMembershipAccess(): void
    {
        $contract = TenantMembershipAccess::class;
        if ($this->app->isAlias($contract) || $this->app->isShared($contract)) {
            return;
        }
        $binding = $this->app->getBindings()[$contract] ?? null;
        if ($binding !== null) {
            if (! is_array($binding)) {
                return;
            }
            $factory = $binding['concrete'] ?? null;
            if (! $factory instanceof Closure || ($binding['shared'] ?? null) !== false) {
                return;
            }
            $reflection = new ReflectionFunction($factory);
            $native = new ReflectionMethod(LaravelContainer::class, 'getClosure');
            if ($reflection->getClosureScopeClass()?->getName() !== LaravelContainer::class
                || $reflection->getFileName() !== $native->getFileName()
                || $reflection->getStartLine() <= $native->getStartLine()
                || $reflection->getEndLine() >= $native->getEndLine()
                || $reflection->getStaticVariables() !== [
                    'abstract' => $contract,
                    'concrete' => DisabledTenantMembershipAccess::class,
                ]) {
                return;
            }

            $this->app->offsetUnset($contract);
        }
        $this->app->scopedIf($contract, AuthTenantMembershipAccess::class);
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

<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Http\Kernel as HttpKernelContract;
use Illuminate\Filesystem\FilesystemServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
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
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Contracts\AcceptInvitationContract;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\AddRolePermissionsContract;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\ApplyRoleTemplateContract;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Contracts\AuthAuditRecorder;
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
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthTenantMembershipAccess;
use Nvl\Auth\Tests\TestCase;
use Nvl\Auth\ValueObjects\ApiTokenSnapshot;
use Nvl\Data\Services\TypeScriptSourceRegistry;
use Nvl\Support\Providers\TenantServiceProvider;
use Nvl\Support\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Support\Tenancy\Services\DisabledTenantMembershipAccess;
use Nvl\Support\Tenancy\ValueObjects\TenantId;
use Nvl\Tenancy\Providers\TenancyServiceProvider;

if (! in_array(dirname(__DIR__).'/Pest.php', get_included_files(), true)) {
    uses(TestCase::class);
}

beforeEach(function (): void {
    config()->set('nvl-auth.features.passkeys.settings.relying_party_id', 'auth-package.test');
    config()->set('nvl-auth.features.passkeys.settings.relying_party_name', 'NVL Auth Test');
    config()->set('nvl-auth.features.passkeys.settings.origins', ['https://auth-package.test']);
});

dataset('auth focused consumer contracts', [
    'CreateApiTokenAction' => [CreateApiTokenContract::class, CreateApiTokenAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ListApiTokensAction' => [ListApiTokensContract::class, ListApiTokensAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true]]],
    'RevokeAllApiTokensAction' => [RevokeAllApiTokensContract::class, RevokeAllApiTokensAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true]]],
    'RevokeApiTokenAction' => [RevokeApiTokenContract::class, RevokeApiTokenAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true]]],
    'RotateApiTokenAction' => [RotateApiTokenContract::class, RotateApiTokenAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'UpdateApiTokenAction' => [UpdateApiTokenContract::class, UpdateApiTokenAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['policy', 'Nvl\\Auth\\Services\\ApiTokenPolicy', false, null, true], ['tokens', 'Nvl\\Auth\\Contracts\\ApiTokenManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ListAuthAuditsAction' => [ListAuthAuditsContract::class, ListAuthAuditsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'ShowAuthAuditAction' => [ShowAuthAuditContract::class, ShowAuthAuditAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'CompletePendingTenantAuthenticationIntentAction' => [CompletePendingTenantAuthenticationIntentContract::class, CompletePendingTenantAuthenticationIntentAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['auth', 'Illuminate\\Auth\\AuthManager', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\TenantAuthenticationSession', false, null, true], ['intents', 'Nvl\\Auth\\Services\\TenantAuthenticationIntents', false, null, true], ['memberships', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'EstablishAuthenticatedSessionAction' => [EstablishAuthenticatedSessionContract::class, EstablishAuthenticatedSessionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['subjects', 'Nvl\\Auth\\Contracts\\AuthSubjectResolver', false, null, true], ['auth', 'Illuminate\\Auth\\AuthManager', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\BrowserSession', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['eligibility', 'Nvl\\Auth\\Contracts\\AuthenticationEligibility', false, null, true], ['loginMetadata', 'Nvl\\Auth\\Contracts\\SuccessfulLoginMetadataRecorder', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationIntents', false, null, true], ['tenantMemberships', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['tenantSession', 'Nvl\\Auth\\Contracts\\TenantAuthenticationSession', false, null, true]]],
    'LoginAction' => [LoginContract::class, LoginAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['auth', 'Illuminate\\Auth\\AuthManager', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\BrowserSession', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['eligibility', 'Nvl\\Auth\\Contracts\\AuthenticationEligibility', false, null, true], ['loginMetadata', 'Nvl\\Auth\\Contracts\\SuccessfulLoginMetadataRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationIntents', false, null, true], ['tenantMemberships', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true]]],
    'LogoutAction' => [LogoutContract::class, LogoutAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['auth', 'Illuminate\\Auth\\AuthManager', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\BrowserSession', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'RequestEmailVerificationAction' => [RequestEmailVerificationContract::class, RequestEmailVerificationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'VerifyEmailAction' => [VerifyEmailContract::class, VerifyEmailAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ConsumeMagicLinkAction' => [ConsumeMagicLinkContract::class, ConsumeMagicLinkAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['challenges', 'Nvl\\Auth\\Actions\\Challenges\\ConsumeChallengeAction', false, null, true], ['directChallenges', 'Nvl\\Auth\\Actions\\Challenges\\ConsumeChallengeByIdAction', false, null, true]]],
    'RequestMagicLinkAction' => [RequestMagicLinkContract::class, RequestMagicLinkAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['challenges', 'Nvl\\Auth\\Actions\\Challenges\\IssueChallengeAction', false, null, true]]],
    'RequestMagicLinkAuthenticationAction' => [RequestMagicLinkAuthenticationContract::class, RequestMagicLinkAuthenticationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['identifiers', 'Nvl\\Auth\\Contracts\\AuthIdentifierResolver', false, null, true], ['links', 'Nvl\\Auth\\Actions\\Challenges\\RequestMagicLinkAction', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationChallengeIntents', false, null, true]]],
    'RequestSecurityCodeAction' => [RequestSecurityCodeContract::class, RequestSecurityCodeAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['challenges', 'Nvl\\Auth\\Actions\\Challenges\\IssueChallengeAction', false, null, true]]],
    'RequestSecurityCodeAuthenticationAction' => [RequestSecurityCodeAuthenticationContract::class, RequestSecurityCodeAuthenticationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['identifiers', 'Nvl\\Auth\\Contracts\\AuthIdentifierResolver', false, null, true], ['codes', 'Nvl\\Auth\\Actions\\Challenges\\RequestSecurityCodeAction', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationChallengeIntents', false, null, true]]],
    'VerifySecurityCodeAction' => [VerifySecurityCodeContract::class, VerifySecurityCodeAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['challenges', 'Nvl\\Auth\\Actions\\Challenges\\ConsumeChallengeAction', false, null, true]]],
    'VerifySecurityCodeAuthenticationAction' => [VerifySecurityCodeAuthenticationContract::class, VerifySecurityCodeAuthenticationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['codes', 'Nvl\\Auth\\Actions\\Challenges\\VerifySecurityCodeAction', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationChallengeIntents', false, null, true], ['sessions', 'Nvl\\Auth\\Actions\\Authentication\\EstablishAuthenticatedSessionAction', false, null, true]]],
    'CreateAuthClientAction' => [CreateAuthClientContract::class, CreateAuthClientAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'DeleteAuthClientAction' => [DeleteAuthClientContract::class, DeleteAuthClientAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'EndAuthClientSessionAction' => [EndAuthClientSessionContract::class, EndAuthClientSessionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ListAuthClientsAction' => [ListAuthClientsContract::class, ListAuthClientsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true]]],
    'RecordAuthClientSessionAction' => [RecordAuthClientSessionContract::class, RecordAuthClientSessionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'SetAuthClientActiveAction' => [SetAuthClientActiveContract::class, SetAuthClientActiveAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ShowAuthClientAction' => [ShowAuthClientContract::class, ShowAuthClientAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true]]],
    'StartAuthClientAction' => [StartAuthClientContract::class, StartAuthClientAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'TouchAuthClientSessionAction' => [TouchAuthClientSessionContract::class, TouchAuthClientSessionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true]]],
    'UpdateAuthClientAction' => [UpdateAuthClientContract::class, UpdateAuthClientAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'AcceptInvitationAction' => [AcceptInvitationContract::class, AcceptInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['recipientProof', 'Nvl\\Auth\\Contracts\\InvitationRecipientProof', false, null, true], ['rbac', 'Nvl\\Auth\\Services\\RbacManager', false, null, true], ['bootstrap', 'Nvl\\Auth\\Services\\InvitationTenantBootstrap', false, null, true], ['runner', 'Nvl\\Support\\Tenancy\\Contracts\\TenantRunner', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\TenantMembershipAssignments', false, null, true], ['membershipAccess', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'CreateInvitationAction' => [CreateInvitationContract::class, CreateInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['tokens', 'Nvl\\Auth\\Services\\OpaqueTokenFactory', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['membershipAccess', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\TenantMembershipAssignments', false, null, true], ['deliveryMetadata', '?Nvl\\Auth\\Services\\InvitationDeliveryMetadataPolicy', true, null, true]]],
    'FindActiveInvitationAction' => [FindActiveInvitationContract::class, FindActiveInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['deliveryMetadata', 'Nvl\\Auth\\Services\\InvitationDeliveryMetadataPolicy', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'ListInvitationProjectionsAction' => [ListInvitationProjectionsContract::class, ListInvitationProjectionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['invitations', 'Nvl\\Auth\\Actions\\Invitations\\ListInvitationsAction', false, null, true], ['deliveryMetadata', 'Nvl\\Auth\\Services\\InvitationDeliveryMetadataPolicy', false, null, true]]],
    'ListInvitationsAction' => [ListInvitationsContract::class, ListInvitationsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'PreviewInvitationAction' => [PreviewInvitationContract::class, PreviewInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['bootstrap', 'Nvl\\Auth\\Services\\InvitationTenantBootstrap', false, null, true], ['runner', 'Nvl\\Support\\Tenancy\\Contracts\\TenantRunner', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'RecordInvitationDeliveryOutcomeAction' => [RecordInvitationDeliveryOutcomeContract::class, RecordInvitationDeliveryOutcomeAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'RegisterInvitationAction' => [RegisterInvitationContract::class, RegisterInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['subjects', 'Nvl\\Auth\\Contracts\\InvitationSubjectResolver', false, null, true], ['recipientProof', 'Nvl\\Auth\\Contracts\\InvitationRecipientProof', false, null, true], ['bootstrap', 'Nvl\\Auth\\Services\\InvitationTenantBootstrap', false, null, true], ['rbac', 'Nvl\\Auth\\Services\\RbacManager', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['runner', 'Nvl\\Support\\Tenancy\\Contracts\\TenantRunner', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\TenantMembershipAssignments', false, null, true], ['membershipAccess', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true]]],
    'ResendInvitationAction' => [ResendInvitationContract::class, ResendInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['tokens', 'Nvl\\Auth\\Services\\OpaqueTokenFactory', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['deliveryMetadata', '?Nvl\\Auth\\Services\\InvitationDeliveryMetadataPolicy', true, null, true]]],
    'RevokeInvitationAction' => [RevokeInvitationContract::class, RevokeInvitationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'EnrollMembershipAction' => [EnrollMembershipContract::class, EnrollMembershipAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['writer', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\TenantMembershipAssignments', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ListMembershipsAction' => [ListMembershipsContract::class, ListMembershipsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['boundary', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true]]],
    'ListOwnMembershipsAction' => [ListOwnMembershipsContract::class, ListOwnMembershipsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'ProvisionTenantOwnerAction' => [ProvisionTenantOwnerContract::class, ProvisionTenantOwnerAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['writer', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RevokeMembershipAction' => [RevokeMembershipContract::class, RevokeMembershipAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipLocator', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['writer', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\TenantMembershipAssignments', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'SetMembershipStatusAction' => [SetMembershipStatusContract::class, SetMembershipStatusAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipLocator', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['writer', 'Nvl\\Auth\\Services\\MembershipWriter', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ShowMembershipAction' => [ShowMembershipContract::class, ShowMembershipAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipLocator', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true]]],
    'TransferMembershipOwnershipAction' => [TransferMembershipOwnershipContract::class, TransferMembershipOwnershipAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\MembershipPrincipalResolver', false, null, true], ['memberships', 'Nvl\\Auth\\Services\\MembershipLocator', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'BeginPasskeyAuthenticationAction' => [BeginPasskeyAuthenticationContract::class, BeginPasskeyAuthenticationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['ceremony', 'Nvl\\Auth\\Contracts\\PasskeyCeremony', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationChallengeIntents', false, null, true]]],
    'BeginPasskeyRegistrationAction' => [BeginPasskeyRegistrationContract::class, BeginPasskeyRegistrationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['ceremony', 'Nvl\\Auth\\Contracts\\PasskeyCeremony', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'FinishPasskeyAuthenticationAction' => [FinishPasskeyAuthenticationContract::class, FinishPasskeyAuthenticationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['ceremony', 'Nvl\\Auth\\Contracts\\PasskeyCeremony', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['input', 'Nvl\\Auth\\Services\\PasskeyInputValidator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenantIntents', 'Nvl\\Auth\\Services\\TenantAuthenticationChallengeIntents', false, null, true]]],
    'FinishPasskeyRegistrationAction' => [FinishPasskeyRegistrationContract::class, FinishPasskeyRegistrationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['ceremony', 'Nvl\\Auth\\Contracts\\PasskeyCeremony', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['input', 'Nvl\\Auth\\Services\\PasskeyInputValidator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RevokePasskeyAction' => [RevokePasskeyContract::class, RevokePasskeyAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ConfirmPasswordAction' => [ConfirmPasswordContract::class, ConfirmPasswordAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Illuminate\\Contracts\\Hashing\\Hasher', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\BrowserSession', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RequestPasswordResetAction' => [RequestPasswordResetContract::class, RequestPasswordResetAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['brokers', 'Illuminate\\Auth\\Passwords\\PasswordBrokerManager', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['eligibility', 'Nvl\\Auth\\Contracts\\AuthenticationEligibility', false, null, true]]],
    'ResetPasswordAction' => [ResetPasswordContract::class, ResetPasswordAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['brokers', 'Illuminate\\Auth\\Passwords\\PasswordBrokerManager', false, null, true], ['passwords', 'Nvl\\Auth\\Contracts\\PasswordUpdater', false, null, true], ['pipeline', 'Nvl\\Auth\\Pipelines\\AuthPipeline', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['eligibility', 'Nvl\\Auth\\Contracts\\AuthenticationEligibility', false, null, true]]],
    'UpdatePasswordAction' => [UpdatePasswordContract::class, UpdatePasswordAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Illuminate\\Contracts\\Hashing\\Hasher', false, null, true], ['passwords', 'Nvl\\Auth\\Contracts\\PasswordUpdater', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'AddRolePermissionsAction' => [AddRolePermissionsContract::class, AddRolePermissionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\RbacAssignmentService', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ApplyRoleTemplateAction' => [ApplyRoleTemplateContract::class, ApplyRoleTemplateAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['templates', 'Nvl\\Auth\\Services\\RoleTemplateRegistry', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['hierarchy', 'Nvl\\Auth\\Services\\RoleHierarchy', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenancy', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'BootstrapRbacAction' => [BootstrapRbacContract::class, BootstrapRbacAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['synchronizer', 'Nvl\\Auth\\Services\\RbacSynchronizer', false, null, true], ['registrar', 'Spatie\\Permission\\PermissionRegistrar', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'CheckRoleNameAvailabilityAction' => [CheckRoleNameAvailabilityContract::class, CheckRoleNameAvailabilityAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['tenancy', 'Nvl\\Auth\\Services\\AuthTenantRbacQueries', false, null, true]]],
    'CloneRoleAction' => [CloneRoleContract::class, CloneRoleAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenancy', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true]]],
    'CreatePermissionAction' => [CreatePermissionContract::class, CreatePermissionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'CreatePermissionWithRolesAction' => [CreatePermissionWithRolesContract::class, CreatePermissionWithRolesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\RbacAssignmentService', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'CreateRoleAction' => [CreateRoleContract::class, CreateRoleAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['hierarchy', 'Nvl\\Auth\\Services\\RoleHierarchy', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['tenancy', 'Nvl\\Support\\Tenancy\\Contracts\\TenantBoundary', false, null, true], ['context', 'Nvl\\Support\\Tenancy\\Contracts\\TenantContext', false, null, true], ['memberships', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true]]],
    'DeletePermissionAction' => [DeletePermissionContract::class, DeletePermissionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'DeleteRoleAction' => [DeleteRoleContract::class, DeleteRoleAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ListPermissionCatalogAction' => [ListPermissionCatalogContract::class, ListPermissionCatalogAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['groupExpressions', 'Nvl\\Auth\\Services\\RbacPermissionGroupExpressions', false, null, true]]],
    'ListPermissionGroupsAction' => [ListPermissionGroupsContract::class, ListPermissionGroupsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['limits', 'Nvl\\Auth\\Services\\RbacConsumerLimits', false, null, true], ['groupExpressions', 'Nvl\\Auth\\Services\\RbacPermissionGroupExpressions', false, null, true]]],
    'ListPermissionOptionsAction' => [ListPermissionOptionsContract::class, ListPermissionOptionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['limits', 'Nvl\\Auth\\Services\\RbacConsumerLimits', false, null, true], ['options', 'Nvl\\Auth\\Services\\RbacOptionReadService', false, null, true]]],
    'ListPermissionsAction' => [ListPermissionsContract::class, ListPermissionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true]]],
    'ListRoleCatalogAction' => [ListRoleCatalogContract::class, ListRoleCatalogAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['tenancy', 'Nvl\\Auth\\Services\\AuthTenantRbacQueries', false, null, true]]],
    'ListRoleHierarchyAction' => [ListRoleHierarchyContract::class, ListRoleHierarchyAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['hierarchy', 'Nvl\\Auth\\Services\\RoleHierarchy', false, null, true], ['tenancy', 'Nvl\\Auth\\Services\\AuthTenantRbacQueries', false, null, true]]],
    'ListRoleOptionsAction' => [ListRoleOptionsContract::class, ListRoleOptionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['limits', 'Nvl\\Auth\\Services\\RbacConsumerLimits', false, null, true], ['options', 'Nvl\\Auth\\Services\\RbacOptionReadService', false, null, true]]],
    'ListRoleTemplatesAction' => [ListRoleTemplatesContract::class, ListRoleTemplatesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['templates', 'Nvl\\Auth\\Services\\RoleTemplateRegistry', false, null, true]]],
    'ListRolesAction' => [ListRolesContract::class, ListRolesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['tenancy', 'Nvl\\Auth\\Services\\AuthTenantRbacQueries', false, null, true]]],
    'ResolvePermissionIdentifiersAction' => [ResolvePermissionIdentifiersContract::class, ResolvePermissionIdentifiersAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true]]],
    'ResolveRoleIdentifiersAction' => [ResolveRoleIdentifiersContract::class, ResolveRoleIdentifiersAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true]]],
    'ShowPermissionAction' => [ShowPermissionContract::class, ShowPermissionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['tenancy', 'Nvl\\Auth\\Services\\AuthTenantRbacQueries', false, null, true]]],
    'ShowRbacAnalyticsAction' => [ShowRbacAnalyticsContract::class, ShowRbacAnalyticsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true]]],
    'ShowRoleAction' => [ShowRoleContract::class, ShowRoleAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true]]],
    'ShowRoleAnalyticsAction' => [ShowRoleAnalyticsContract::class, ShowRoleAnalyticsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['principalAttributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['groupExpressions', 'Nvl\\Auth\\Services\\RbacPermissionGroupExpressions', false, null, true]]],
    'SuggestPermissionsAction' => [SuggestPermissionsContract::class, SuggestPermissionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['limits', 'Nvl\\Auth\\Services\\RbacConsumerLimits', false, null, true], ['options', 'Nvl\\Auth\\Services\\RbacOptionReadService', false, null, true]]],
    'SuggestRolesAction' => [SuggestRolesContract::class, SuggestRolesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['limits', 'Nvl\\Auth\\Services\\RbacConsumerLimits', false, null, true], ['options', 'Nvl\\Auth\\Services\\RbacOptionReadService', false, null, true]]],
    'SyncRolePermissionsAction' => [SyncRolePermissionsContract::class, SyncRolePermissionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['assignments', 'Nvl\\Auth\\Services\\RbacAssignmentService', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'SynchronizePermissionCatalogAction' => [SynchronizePermissionCatalogContract::class, SynchronizePermissionCatalogAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['synchronizer', 'Nvl\\Auth\\Services\\RbacSynchronizer', false, null, true], ['registrar', 'Spatie\\Permission\\PermissionRegistrar', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'SynchronizeRbacAction' => [SynchronizeRbacContract::class, SynchronizeRbacAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['synchronizer', 'Nvl\\Auth\\Services\\RbacSynchronizer', false, null, true], ['registrar', 'Spatie\\Permission\\PermissionRegistrar', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'SynchronizeRoleTemplatesAction' => [SynchronizeRoleTemplatesContract::class, SynchronizeRoleTemplatesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['synchronizer', 'Nvl\\Auth\\Services\\RbacSynchronizer', false, null, true], ['registrar', 'Spatie\\Permission\\PermissionRegistrar', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'UpdatePermissionAction' => [UpdatePermissionContract::class, UpdatePermissionAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'UpdateRoleAction' => [UpdateRoleContract::class, UpdateRoleAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['entities', 'Nvl\\Auth\\Services\\RbacEntityLocator', false, null, true], ['hierarchy', 'Nvl\\Auth\\Services\\RoleHierarchy', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'ConsumeRecoveryCodeAction' => [ConsumeRecoveryCodeContract::class, ConsumeRecoveryCodeAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RegenerateRecoveryCodesAction' => [RegenerateRecoveryCodesContract::class, RegenerateRecoveryCodesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RevokeRecoveryCodesAction' => [RevokeRecoveryCodesContract::class, RevokeRecoveryCodesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'CompleteSocialAuthorizationAction' => [CompleteSocialAuthorizationContract::class, CompleteSocialAuthorizationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\SocialProviderConfiguration', false, null, true], ['provider', 'Nvl\\Auth\\Contracts\\SocialIdentityProvider', false, null, true], ['subjects', 'Nvl\\Auth\\Contracts\\SocialSubjectResolver', false, null, true], ['links', 'Nvl\\Auth\\Actions\\SocialIdentities\\LinkSocialIdentityAction', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true], ['intents', 'Nvl\\Auth\\Services\\TenantAuthenticationIntents', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\TenantAuthenticationSession', false, null, true], ['memberships', 'Nvl\\Support\\Tenancy\\Contracts\\TenantMembershipAccess', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'LinkSocialIdentityAction' => [LinkSocialIdentityContract::class, LinkSocialIdentityAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['hasher', 'Nvl\\Auth\\Services\\SecretHasher', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'RevokeSocialIdentityAction' => [RevokeSocialIdentityContract::class, RevokeSocialIdentityAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'StartSocialAuthorizationAction' => [StartSocialAuthorizationContract::class, StartSocialAuthorizationAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\SocialProviderConfiguration', false, null, true], ['provider', 'Nvl\\Auth\\Contracts\\SocialIdentityProvider', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true], ['intents', 'Nvl\\Auth\\Services\\TenantAuthenticationIntents', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\TenantAuthenticationSession', false, null, true]]],
    'ConfirmTotpEnrollmentAction' => [ConfirmTotpEnrollmentContract::class, ConfirmTotpEnrollmentAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['totp', 'Nvl\\Auth\\Services\\TotpEngine', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'RevokeTotpCredentialAction' => [RevokeTotpCredentialContract::class, RevokeTotpCredentialAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'StartTotpEnrollmentAction' => [StartTotpEnrollmentContract::class, StartTotpEnrollmentAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['totp', 'Nvl\\Auth\\Services\\TotpEngine', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'VerifyTotpAction' => [VerifyTotpContract::class, VerifyTotpAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['totp', 'Nvl\\Auth\\Services\\TotpEngine', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'BulkUpdateUsersAction' => [BulkUpdateUsersContract::class, BulkUpdateUsersAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['sessions', 'Nvl\\Auth\\Contracts\\PrincipalSessionContainment', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true]]],
    'CreateUserAction' => [CreateUserContract::class, CreateUserAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['models', 'Nvl\\Auth\\Services\\AuthModelRegistry', false, null, true], ['rbac', 'Nvl\\Auth\\Services\\RbacManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true]]],
    'DeleteOwnAccountAction' => [DeleteOwnAccountContract::class, DeleteOwnAccountAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['confirmation', 'Nvl\\Auth\\Contracts\\AccountConfirmation', false, null, true], ['auth', 'Illuminate\\Auth\\AuthManager', false, null, true], ['session', 'Nvl\\Auth\\Contracts\\BrowserSession', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true]]],
    'DeleteUserAction' => [DeleteUserContract::class, DeleteUserAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['sessions', 'Nvl\\Auth\\Contracts\\PrincipalSessionContainment', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true]]],
    'ListUsersAction' => [ListUsersContract::class, ListUsersAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true]]],
    'RestoreUserAction' => [RestoreUserContract::class, RestoreUserAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['sessions', 'Nvl\\Auth\\Contracts\\PrincipalSessionContainment', false, null, true]]],
    'SetUserActiveAction' => [SetUserActiveContract::class, SetUserActiveAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['sessions', 'Nvl\\Auth\\Contracts\\PrincipalSessionContainment', false, null, true], ['owners', 'Nvl\\Auth\\Services\\MembershipOwnerGuard', false, null, true]]],
    'ShowProfileAction' => [ShowProfileContract::class, ShowProfileAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'ShowUserAction' => [ShowUserContract::class, ShowUserAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true]]],
    'SuggestUsersAction' => [SuggestUsersContract::class, SuggestUsersAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true]]],
    'SyncUserPermissionsAction' => [SyncUserPermissionsContract::class, SyncUserPermissionsAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\RbacPrincipalAccess', false, null, true], ['rbac', 'Nvl\\Auth\\Services\\RbacManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'SyncUserRolesAction' => [SyncUserRolesContract::class, SyncUserRolesAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\MutationAuthorizer', false, null, true], ['principals', 'Nvl\\Auth\\Contracts\\RbacPrincipalAccess', false, null, true], ['rbac', 'Nvl\\Auth\\Services\\RbacManager', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true]]],
    'UpdateProfileAction' => [UpdateProfileContract::class, UpdateProfileAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true], ['confirmation', 'Nvl\\Auth\\Contracts\\AccountConfirmation', false, null, true], ['configuration', 'Nvl\\Auth\\Services\\AuthConfiguration', false, null, true], ['operations', 'Nvl\\Auth\\Services\\AuthOperationBoundary', false, null, true]]],
    'UpdateUserAction' => [UpdateUserContract::class, UpdateUserAction::class, [['features', 'Nvl\\Auth\\Services\\FeatureGate', false, null, true], ['authorization', 'Nvl\\Auth\\Services\\ManagementAuthorizer', false, null, true], ['users', 'Nvl\\Auth\\Services\\UserLocator', false, null, true], ['audits', 'Nvl\\Auth\\Contracts\\AuthAuditRecorder', false, null, true], ['attributes', 'Nvl\\Auth\\Contracts\\PrincipalAttributeMapper', false, null, true]]],
]);

it('preserves each focused execute contract and the original concrete constructor', function (string $contract, string $implementation, array $constructorParameters): void {
    expect(interface_exists($contract))->toBeTrue();
    $interface = new ReflectionClass($contract);
    $concrete = new ReflectionClass($implementation);
    expect($concrete->implementsInterface($contract))->toBeTrue()
        ->and($concrete->isFinal())->toBeTrue()
        ->and($concrete->isReadOnly())->toBeTrue()
        ->and(array_map(static fn (ReflectionMethod $method): string => $method->getName(), $interface->getMethods()))->toBe(['execute']);
    $native = $concrete->getMethod('execute');
    $declared = $interface->getMethod('execute');
    expect((string) $declared->getReturnType())->toBe((string) $native->getReturnType())
        ->and($declared->getDocComment())->toBe($native->getDocComment())
        ->and(count($declared->getParameters()))->toBe(count($native->getParameters()));
    foreach ($native->getParameters() as $position => $parameter) {
        $copied = $declared->getParameters()[$position];
        expect($copied->getName())->toBe($parameter->getName())
            ->and((string) $copied->getType())->toBe((string) $parameter->getType())
            ->and($copied->isOptional())->toBe($parameter->isOptional())
            ->and($copied->isPassedByReference())->toBe($parameter->isPassedByReference())
            ->and($copied->isVariadic())->toBe($parameter->isVariadic())
            ->and($copied->isDefaultValueAvailable())->toBe($parameter->isDefaultValueAvailable())
            ->and(array_map(static fn (ReflectionAttribute $attribute): array => [$attribute->getName(), $attribute->getArguments()], $copied->getAttributes()))
            ->toBe(array_map(static fn (ReflectionAttribute $attribute): array => [$attribute->getName(), $attribute->getArguments()], $parameter->getAttributes()));
        if ($parameter->isDefaultValueAvailable()) {
            expect($copied->getDefaultValue())->toEqual($parameter->getDefaultValue());
        }
    }
    $constructor = $concrete->getConstructor() ?? throw new LogicException('Concrete constructor missing.');
    expect(array_map(static fn (ReflectionParameter $parameter): array => [
        $parameter->getName(), (string) $parameter->getType(), $parameter->isDefaultValueAvailable(),
        $parameter->isDefaultValueAvailable() ? $parameter->getDefaultValue() : null, $parameter->isPromoted(),
    ], $constructor->getParameters()))->toBe($constructorParameters);
})->with('auth focused consumer contracts');

it('resolves every transient focused default and retains direct concrete construction', function (): void {
    foreach (authFocusedContractPairs() as [$contract, $implementation]) {
        expect($this->app->bound($contract))->toBeTrue();
        expect($this->app->getBindings()[$contract]['shared'])->toBeFalse()
            ->and($this->app->make($contract))->toBeInstanceOf($implementation)
            ->and($this->app->make($implementation))->toBeInstanceOf($implementation);
    }
});

it('accepts a late host instance after every focused default has already resolved', function (): void {
    foreach (authFocusedContractPairs() as [$contract, $implementation]) {
        expect($this->app->make($contract))->toBeInstanceOf($implementation);
        $host = Mockery::mock($contract);
        $this->app->instance($contract, $host);
        expect($this->app->make($contract))->toBe($host);
    }
});

it('preserves focused host instances and closures through provider registration and late replacement', function (): void {
    $consumer = authContractConsumer($this->app);
    try {
        $hosts = [];
        foreach (authFocusedContractPairs() as [$contract]) {
            expect(interface_exists($contract))->toBeTrue();
            $hosts[$contract] = Mockery::mock($contract);
            $consumer->instance($contract, $hosts[$contract]);
        }
        (new AuthServiceProvider($consumer))->register();
        foreach ($hosts as $contract => $host) {
            expect($consumer->make($contract))->toBe($host);
            $late = Mockery::mock($contract);
            $consumer->instance($contract, $late);
            expect($consumer->make($contract))->toBe($late);
        }
        $contract = ListApiTokensContract::class;
        $consumer->offsetUnset($contract);
        $factory = static fn (): never => throw new LogicException('Host closure must remain lazy.');
        $consumer->bind($contract, $factory);
        (new AuthServiceProvider($consumer))->register();
        expect($consumer->getBindings()[$contract]['concrete'])->toBe($factory);
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
});

it('preserves every public extension host instance and lazy factory without changing native lifetimes', function (): void {
    $consumer = authContractConsumer($this->app);
    try {
        foreach (authPublicExtensionContracts() as [$contract]) {
            $host = Mockery::mock($contract);
            $consumer->instance($contract, $host);
        }
        $instances = [];
        foreach (authPublicExtensionContracts() as [$contract]) {
            $instances[$contract] = $consumer->make($contract);
        }
        (new AuthServiceProvider($consumer))->register();
        $consumer->forgetScopedInstances();
        foreach ($instances as $contract => $host) {
            expect($consumer->getBindings()[$contract] ?? null)->toBeNull();
            expect($consumer->make($contract))->toBe($host);
            $consumer->offsetUnset($contract);
            $factory = static fn (): never => throw new LogicException('A host extension must not execute at registration.');
            $consumer->bind($contract, $factory);
        }
        (new AuthServiceProvider($consumer))->register();
        foreach (authPublicExtensionContracts() as [$contract]) {
            expect($consumer->getBindings()[$contract]['shared'])->toBeFalse();
            expect(fn () => $consumer->make($contract))->toThrow(LogicException::class, 'A host extension must not execute at registration.');
        }
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
    foreach (authPublicExtensionContracts() as [$contract, $scoped]) {
        $this->app->offsetUnset($contract);
    }
    (new AuthServiceProvider($this->app))->register();
    foreach (authPublicExtensionContracts() as [$contract, $scoped]) {
        $first = $this->app->make($contract);
        expect($this->app->getBindings()[$contract]['shared'])->toBeTrue()
            ->and($this->app->make($contract))->toBe($first);
        $this->app->forgetScopedInstances();
        expect($this->app->make($contract) === $first)->toBe(! $scoped);
    }
});

it('runs real host generic DTO and void orchestration without package work or side effects', function (): void {
    expect(interface_exists(ListApiTokensContract::class))->toBeTrue()
        ->and(interface_exists(ListInvitationProjectionsContract::class))->toBeTrue()
        ->and(interface_exists(LogoutContract::class))->toBeTrue();
    expect($this->app->make(ListApiTokensContract::class))->toBeInstanceOf(ListApiTokensAction::class)
        ->and($this->app->make(ListInvitationProjectionsContract::class))->toBeInstanceOf(ListInvitationProjectionsAction::class)
        ->and($this->app->make(LogoutContract::class))->toBeInstanceOf(LogoutAction::class);
    $actor = User::factory()->make(['id' => '00000000-0000-4000-8000-000000000021']);
    $token = new ApiTokenSnapshot('token-42', 'Host dashboard', ['profile:read'], null, null, CarbonImmutable::parse('2026-10-06T12:00:00Z'));
    $invitation = new InvitationReadData(
        id: '00000000-0000-4000-8000-000000000042', recipient: 'invitee@example.test', type: 'user', purpose: 'registration',
        inviter: null, acceptedBy: null, roles: [], permissions: [], metadata: [], lifecycle: 'active', resendCount: 0,
        lastSentAt: null, expiresAt: CarbonImmutable::parse('2026-10-07T12:00:00Z'), acceptedAt: null, revokedAt: null,
        deliveryStatus: null, deliveryAttemptedAt: null, deliveredAt: null, deliveryFailedAt: null, deliveryFailureCode: null,
    );
    $page = new LengthAwarePaginator([$invitation], 1, 10, 1);
    $tokens = Mockery::mock(ListApiTokensContract::class);
    $tokens->shouldReceive('execute')->once()->with($actor)->andReturn([$token]);
    $invitations = Mockery::mock(ListInvitationProjectionsContract::class);
    $invitations->shouldReceive('execute')->once()->with($actor, null, 10)->andReturn($page);
    $logout = Mockery::mock(LogoutContract::class);
    $logout->shouldReceive('execute')->once()->withNoArgs()->andReturnNull();
    $this->app->instance(ListApiTokensContract::class, $tokens);
    $this->app->instance(ListInvitationProjectionsContract::class, $invitations);
    $this->app->instance(LogoutContract::class, $logout);
    Event::fake();
    Queue::fake();
    Notification::fake();
    Http::preventStrayRequests();
    $connection = DB::connection();
    $connection->flushQueryLog();
    $connection->enableQueryLog();
    try {
        foreach ([ListApiTokensAction::class, ListInvitationProjectionsAction::class, ListInvitationsAction::class, LogoutAction::class,
            ApiTokenManager::class, AuthManager::class, BrowserSession::class, AuthPipeline::class] as $implementation) {
            $this->app->beforeResolving($implementation, static fn (): never => throw new LogicException('Real Auth work must not resolve: '.$implementation));
        }
        $workflow = $this->app->make(AuthConsumerWorkflow::class);
        expect($workflow->tokenNames($actor))->toBe(['Host dashboard'])
            ->and($workflow->invitationRecipients($actor))->toBe(['invitee@example.test'])
            ->and($workflow->signOut())->toBe('/signed-out')
            ->and($connection->getQueryLog())->toBe([]);
        Queue::assertNothingPushed();
        Event::assertNothingDispatched();
        Notification::assertNothingSent();
    } finally {
        $connection->disableQueryLog();
    }
});

it('drops native scoped current request and late fakes across scopes and two applications', function (): void {
    $this->app->forgetScopedInstances();
    $requestA = Request::create('/first', server: ['REMOTE_ADDR' => '192.0.2.1', 'HTTP_USER_AGENT' => 'Host A', 'HTTP_X_REQUEST_ID' => 'request-a']);
    $requestA->setLaravelSession(new Store('host-a', new ArraySessionHandler(120)));
    $this->app->instance('request', $requestA);
    $firstContext = $this->app->make(AuthAuditContextProvider::class);
    $firstBrowser = $this->app->make(BrowserSession::class);
    $firstTenant = $this->app->make(TenantAuthenticationSession::class);
    expect($firstContext->requestId())->toBe('request-a');
    $firstTenant->storeAuthenticationIntent('github', 'nonce-a');
    $fake = Mockery::mock(BrowserSession::class);
    $this->app->instance(BrowserSession::class, $fake);
    $this->app->forgetScopedInstances();
    $requestB = Request::create('/second', server: ['REMOTE_ADDR' => '192.0.2.2', 'HTTP_USER_AGENT' => 'Host B', 'HTTP_X_REQUEST_ID' => 'request-b']);
    $requestB->setLaravelSession(new Store('host-b', new ArraySessionHandler(120)));
    $this->app->instance('request', $requestB);
    $nextContext = $this->app->make(AuthAuditContextProvider::class);
    $nextBrowser = $this->app->make(BrowserSession::class);
    $nextTenant = $this->app->make(TenantAuthenticationSession::class);
    expect($nextContext)->not->toBe($firstContext)
        ->and($nextContext->requestId())->toBe('request-b')
        ->and($nextContext->ipAddress())->toBe('192.0.2.2')
        ->and($nextContext->userAgent())->toBe('Host B')
        ->and($nextBrowser)->not->toBe($firstBrowser)->not->toBe($fake)
        ->and($nextTenant)->not->toBe($firstTenant)
        ->and($nextTenant->pullAuthenticationIntent('github'))->toBeNull();
    $this->app->instance(BrowserSession::class, $fake);
    $second = $this->createApplication();
    try {
        expect($second->make(BrowserSession::class))->toBeInstanceOf(LaravelBrowserSession::class)->not->toBe($fake)
            ->and($second->make(AuthAuditContextProvider::class))->not->toBe($nextContext)
            ->and($this->app->make(BrowserSession::class))->toBe($fake);
    } finally {
        Container::setInstance($this->app);
        Facade::setFacadeApplication($this->app);
        Facade::clearResolvedInstances();
        $second->flush();
    }
});

it('replaces only the native transient Core membership fallback even after earlier resolution', function (bool $resolved, string $order): void {
    $consumer = authContractConsumer($this->app);
    try {
        $provider = new AuthServiceProvider($consumer);
        if ($order === 'core first') {
            $consumer->register(TenantServiceProvider::class);
        } elseif ($order === 'tenancy first') {
            $consumer->register(TenancyServiceProvider::class);
        }
        $provider->register();
        if ($order === 'auth first') {
            $consumer->register(TenancyServiceProvider::class);
        }
        $old = $resolved ? $consumer->make(TenantMembershipAccess::class) : null;
        expect($consumer->isShared(TenantMembershipAccess::class))->toBeFalse();
        $factoryResolutions = 0;
        $consumer->beforeResolving(AuthTenantMembershipAccess::class, static function () use (&$factoryResolutions): void {
            $factoryResolutions++;
        });
        if ($resolved) {
            $consumer->rebinding(TenantMembershipAccess::class, static function (): void {});
        }
        authBootMembershipProvider($consumer, $this->app);
        expect($factoryResolutions)->toBe(0);
        $current = $consumer->make(TenantMembershipAccess::class);
        expect($current)->toBeInstanceOf(AuthTenantMembershipAccess::class)
            ->and($consumer->make(TenantMembershipAccess::class))->toBe($current);
        if ($resolved) {
            expect($old)->not->toBe($current);
        }
        $host = new AuthHostMembershipAccess;
        $consumer->instance(TenantMembershipAccess::class, $host);
        authBootMembershipProvider($consumer, $this->app);
        expect($consumer->make(TenantMembershipAccess::class))->toBe($host);
        $consumer->forgetScopedInstances();
        expect($consumer->make(TenantMembershipAccess::class))->toBeInstanceOf(AuthTenantMembershipAccess::class)->not->toBe($current);
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
})->with([[false, 'core first'], [true, 'core first'], [false, 'tenancy first'], [true, 'tenancy first'], [false, 'auth first'], [true, 'auth first']]);

it('preserves genuine neutral membership hosts lazily in both provider orders', function (string $kind, bool $hostFirst): void {
    $consumer = authContractConsumer($this->app);
    try {
        $host = $kind === 'fallback instance' ? new DisabledTenantMembershipAccess : new AuthHostMembershipAccess;
        $abstract = TenantMembershipAccess::class;
        $concrete = DisabledTenantMembershipAccess::class;
        $factory = $kind === 'lookalike closure'
            ? static function () use ($abstract, $concrete): never {
                throw new LogicException('Native-looking host factory must not run: '.$abstract.$concrete);
            }
        : static fn (): never => throw new LogicException('Host membership closure cannot run at registration.');
        $install = static function () use ($consumer, $kind, $host, $factory): void {
            match ($kind) {
                'instance', 'fallback instance' => $consumer->instance(TenantMembershipAccess::class, $host),
                'alias' => (static function () use ($consumer, $host): void {
                    $consumer->instance('host.memberships', $host);
                    $consumer->alias('host.memberships', TenantMembershipAccess::class);
                })(),
                'closure', 'lookalike closure' => $consumer->bind(TenantMembershipAccess::class, $factory),
                'class' => $consumer->bind(TenantMembershipAccess::class, AuthHostMembershipAccess::class),
                'singleton' => $consumer->singleton(TenantMembershipAccess::class, AuthHostMembershipAccess::class),
                'shared fallback' => $consumer->singleton(TenantMembershipAccess::class, DisabledTenantMembershipAccess::class),
                default => throw new LogicException('Unknown fixture binding.'),
            };
        };
        if ($hostFirst) {
            $install();
        }
        (new AuthServiceProvider($consumer))->register();
        if (! $hostFirst) {
            $install();
        }
        $binding = $consumer->getBindings()[TenantMembershipAccess::class] ?? null;
        authBootMembershipProvider($consumer, $this->app);
        expect($consumer->getBindings()[TenantMembershipAccess::class] ?? null)->toBe($binding);
        if (in_array($kind, ['closure', 'lookalike closure'], true)) {
            expect($binding['concrete'] ?? null)->toBe($factory);
        } elseif (in_array($kind, ['instance', 'fallback instance', 'alias'], true)) {
            expect($consumer->make(TenantMembershipAccess::class))->toBe($host);
        } else {
            expect($consumer->make(TenantMembershipAccess::class))->toBeInstanceOf($kind === 'shared fallback' ? DisabledTenantMembershipAccess::class : AuthHostMembershipAccess::class);
        }
    } finally {
        Container::setInstance($this->app);
        $consumer->flush();
    }
})->with((static function (): array {
    $cases = [];
    foreach (['instance', 'fallback instance', 'alias', 'closure', 'lookalike closure', 'class', 'singleton', 'shared fallback'] as $kind) {
        foreach ([false, true] as $hostFirst) {
            $cases[$kind.' '.($hostFirst ? 'before' : 'after')] = [$kind, $hostFirst];
        }
    }

    return $cases;
})());

/** Build a real passive host container without using any package workflow. */
function authContractConsumer(Application $origin): Application
{
    $consumer = new Application($origin->basePath());
    $consumer->instance('config', new Repository($origin->make('config')->all()));
    $consumer->instance('env', 'testing');
    $consumer->instance('db', $origin->make('db'));
    $consumer->instance('events', $origin->make('events'));
    $consumer->instance('cache', $origin->make('cache'));
    $consumer->make('config')->set('nvl-tenancy.directory.driver', 'package');
    $consumer->make('config')->set('nvl-auth.adoption.spatie_storage.enabled', false);
    $consumer->make('config')->set('nvl-auth.adoption.principal_model.enabled', false);
    $consumer->make('config')->set('nvl-auth.adoption.password_broker.enabled', false);
    $consumer->register(FilesystemServiceProvider::class);

    return $consumer;
}

/** Boot the enabled membership adapter while leaving host storage/adoption untouched. */
function authBootMembershipProvider(Application $consumer, Application $origin): void
{
    $consumer->make('config')->set('nvl-tenancy.enabled', true);
    $consumer->make('config')->set('nvl-auth.features.memberships.enabled', true);
    $consumer->make('config')->set('nvl-auth.features.rbac.enabled', false);
    $consumer->make('config')->set('nvl-auth.migrations.enabled', false);
    $consumer->make('config')->set('nvl-auth.adoption.spatie_storage.enabled', false);
    $consumer->instance(HttpKernelContract::class, $origin->make(HttpKernelContract::class));
    $consumer->instance(MembershipPrincipalResolver::class, $origin->make(MembershipPrincipalResolver::class));
    (new AuthServiceProvider($consumer))->boot($consumer->make(AuthConfiguration::class), $consumer->make(TypeScriptSourceRegistry::class));
}

/** A real host service which turns package results into its own presentation. */
final readonly class AuthConsumerWorkflow
{
    public function __construct(private ListApiTokensContract $tokens, private ListInvitationProjectionsContract $invitations, private LogoutContract $logout) {}

    /** @return list<string> */
    public function tokenNames(Authenticatable $actor): array
    {
        return array_map(static fn (ApiTokenSnapshot $token): string => $token->name, $this->tokens->execute($actor));
    }

    /** @return list<string> */
    public function invitationRecipients(Authenticatable $actor): array
    {
        return array_map(static fn (InvitationReadData $invitation): string => $invitation->recipient, $this->invitations->execute($actor, null, 10)->items());
    }

    /** Continue host orchestration after the void package boundary. */
    public function signOut(): string
    {
        $this->logout->execute();

        return '/signed-out';
    }
}

/** A genuine host membership adapter unrelated to Core's disabled fallback. */
final class AuthHostMembershipAccess implements TenantMembershipAccess
{
    public function assertMember(Authenticatable $actor, TenantId $tenant): void {}
}

/** @return list<array{class-string, class-string}> */
function authFocusedContractPairs(): array
{
    return [
        [CreateApiTokenContract::class, CreateApiTokenAction::class],
        [ListApiTokensContract::class, ListApiTokensAction::class],
        [RevokeAllApiTokensContract::class, RevokeAllApiTokensAction::class],
        [RevokeApiTokenContract::class, RevokeApiTokenAction::class],
        [RotateApiTokenContract::class, RotateApiTokenAction::class],
        [UpdateApiTokenContract::class, UpdateApiTokenAction::class],
        [ListAuthAuditsContract::class, ListAuthAuditsAction::class],
        [ShowAuthAuditContract::class, ShowAuthAuditAction::class],
        [CompletePendingTenantAuthenticationIntentContract::class, CompletePendingTenantAuthenticationIntentAction::class],
        [EstablishAuthenticatedSessionContract::class, EstablishAuthenticatedSessionAction::class],
        [LoginContract::class, LoginAction::class],
        [LogoutContract::class, LogoutAction::class],
        [RequestEmailVerificationContract::class, RequestEmailVerificationAction::class],
        [VerifyEmailContract::class, VerifyEmailAction::class],
        [ConsumeMagicLinkContract::class, ConsumeMagicLinkAction::class],
        [RequestMagicLinkContract::class, RequestMagicLinkAction::class],
        [RequestMagicLinkAuthenticationContract::class, RequestMagicLinkAuthenticationAction::class],
        [RequestSecurityCodeContract::class, RequestSecurityCodeAction::class],
        [RequestSecurityCodeAuthenticationContract::class, RequestSecurityCodeAuthenticationAction::class],
        [VerifySecurityCodeContract::class, VerifySecurityCodeAction::class],
        [VerifySecurityCodeAuthenticationContract::class, VerifySecurityCodeAuthenticationAction::class],
        [CreateAuthClientContract::class, CreateAuthClientAction::class],
        [DeleteAuthClientContract::class, DeleteAuthClientAction::class],
        [EndAuthClientSessionContract::class, EndAuthClientSessionAction::class],
        [ListAuthClientsContract::class, ListAuthClientsAction::class],
        [RecordAuthClientSessionContract::class, RecordAuthClientSessionAction::class],
        [SetAuthClientActiveContract::class, SetAuthClientActiveAction::class],
        [ShowAuthClientContract::class, ShowAuthClientAction::class],
        [StartAuthClientContract::class, StartAuthClientAction::class],
        [TouchAuthClientSessionContract::class, TouchAuthClientSessionAction::class],
        [UpdateAuthClientContract::class, UpdateAuthClientAction::class],
        [AcceptInvitationContract::class, AcceptInvitationAction::class],
        [CreateInvitationContract::class, CreateInvitationAction::class],
        [FindActiveInvitationContract::class, FindActiveInvitationAction::class],
        [ListInvitationProjectionsContract::class, ListInvitationProjectionsAction::class],
        [ListInvitationsContract::class, ListInvitationsAction::class],
        [PreviewInvitationContract::class, PreviewInvitationAction::class],
        [RecordInvitationDeliveryOutcomeContract::class, RecordInvitationDeliveryOutcomeAction::class],
        [RegisterInvitationContract::class, RegisterInvitationAction::class],
        [ResendInvitationContract::class, ResendInvitationAction::class],
        [RevokeInvitationContract::class, RevokeInvitationAction::class],
        [EnrollMembershipContract::class, EnrollMembershipAction::class],
        [ListMembershipsContract::class, ListMembershipsAction::class],
        [ListOwnMembershipsContract::class, ListOwnMembershipsAction::class],
        [ProvisionTenantOwnerContract::class, ProvisionTenantOwnerAction::class],
        [RevokeMembershipContract::class, RevokeMembershipAction::class],
        [SetMembershipStatusContract::class, SetMembershipStatusAction::class],
        [ShowMembershipContract::class, ShowMembershipAction::class],
        [TransferMembershipOwnershipContract::class, TransferMembershipOwnershipAction::class],
        [BeginPasskeyAuthenticationContract::class, BeginPasskeyAuthenticationAction::class],
        [BeginPasskeyRegistrationContract::class, BeginPasskeyRegistrationAction::class],
        [FinishPasskeyAuthenticationContract::class, FinishPasskeyAuthenticationAction::class],
        [FinishPasskeyRegistrationContract::class, FinishPasskeyRegistrationAction::class],
        [RevokePasskeyContract::class, RevokePasskeyAction::class],
        [ConfirmPasswordContract::class, ConfirmPasswordAction::class],
        [RequestPasswordResetContract::class, RequestPasswordResetAction::class],
        [ResetPasswordContract::class, ResetPasswordAction::class],
        [UpdatePasswordContract::class, UpdatePasswordAction::class],
        [AddRolePermissionsContract::class, AddRolePermissionsAction::class],
        [ApplyRoleTemplateContract::class, ApplyRoleTemplateAction::class],
        [BootstrapRbacContract::class, BootstrapRbacAction::class],
        [CheckRoleNameAvailabilityContract::class, CheckRoleNameAvailabilityAction::class],
        [CloneRoleContract::class, CloneRoleAction::class],
        [CreatePermissionContract::class, CreatePermissionAction::class],
        [CreatePermissionWithRolesContract::class, CreatePermissionWithRolesAction::class],
        [CreateRoleContract::class, CreateRoleAction::class],
        [DeletePermissionContract::class, DeletePermissionAction::class],
        [DeleteRoleContract::class, DeleteRoleAction::class],
        [ListPermissionCatalogContract::class, ListPermissionCatalogAction::class],
        [ListPermissionGroupsContract::class, ListPermissionGroupsAction::class],
        [ListPermissionOptionsContract::class, ListPermissionOptionsAction::class],
        [ListPermissionsContract::class, ListPermissionsAction::class],
        [ListRoleCatalogContract::class, ListRoleCatalogAction::class],
        [ListRoleHierarchyContract::class, ListRoleHierarchyAction::class],
        [ListRoleOptionsContract::class, ListRoleOptionsAction::class],
        [ListRoleTemplatesContract::class, ListRoleTemplatesAction::class],
        [ListRolesContract::class, ListRolesAction::class],
        [ResolvePermissionIdentifiersContract::class, ResolvePermissionIdentifiersAction::class],
        [ResolveRoleIdentifiersContract::class, ResolveRoleIdentifiersAction::class],
        [ShowPermissionContract::class, ShowPermissionAction::class],
        [ShowRbacAnalyticsContract::class, ShowRbacAnalyticsAction::class],
        [ShowRoleContract::class, ShowRoleAction::class],
        [ShowRoleAnalyticsContract::class, ShowRoleAnalyticsAction::class],
        [SuggestPermissionsContract::class, SuggestPermissionsAction::class],
        [SuggestRolesContract::class, SuggestRolesAction::class],
        [SyncRolePermissionsContract::class, SyncRolePermissionsAction::class],
        [SynchronizePermissionCatalogContract::class, SynchronizePermissionCatalogAction::class],
        [SynchronizeRbacContract::class, SynchronizeRbacAction::class],
        [SynchronizeRoleTemplatesContract::class, SynchronizeRoleTemplatesAction::class],
        [UpdatePermissionContract::class, UpdatePermissionAction::class],
        [UpdateRoleContract::class, UpdateRoleAction::class],
        [ConsumeRecoveryCodeContract::class, ConsumeRecoveryCodeAction::class],
        [RegenerateRecoveryCodesContract::class, RegenerateRecoveryCodesAction::class],
        [RevokeRecoveryCodesContract::class, RevokeRecoveryCodesAction::class],
        [CompleteSocialAuthorizationContract::class, CompleteSocialAuthorizationAction::class],
        [LinkSocialIdentityContract::class, LinkSocialIdentityAction::class],
        [RevokeSocialIdentityContract::class, RevokeSocialIdentityAction::class],
        [StartSocialAuthorizationContract::class, StartSocialAuthorizationAction::class],
        [ConfirmTotpEnrollmentContract::class, ConfirmTotpEnrollmentAction::class],
        [RevokeTotpCredentialContract::class, RevokeTotpCredentialAction::class],
        [StartTotpEnrollmentContract::class, StartTotpEnrollmentAction::class],
        [VerifyTotpContract::class, VerifyTotpAction::class],
        [BulkUpdateUsersContract::class, BulkUpdateUsersAction::class],
        [CreateUserContract::class, CreateUserAction::class],
        [DeleteOwnAccountContract::class, DeleteOwnAccountAction::class],
        [DeleteUserContract::class, DeleteUserAction::class],
        [ListUsersContract::class, ListUsersAction::class],
        [RestoreUserContract::class, RestoreUserAction::class],
        [SetUserActiveContract::class, SetUserActiveAction::class],
        [ShowProfileContract::class, ShowProfileAction::class],
        [ShowUserContract::class, ShowUserAction::class],
        [SuggestUsersContract::class, SuggestUsersAction::class],
        [SyncUserPermissionsContract::class, SyncUserPermissionsAction::class],
        [SyncUserRolesContract::class, SyncUserRolesAction::class],
        [UpdateProfileContract::class, UpdateProfileAction::class],
        [UpdateUserContract::class, UpdateUserAction::class],
    ];
}

/** @return list<array{class-string, bool}> */
function authPublicExtensionContracts(): array
{
    return [
        [AuthAuditRecorder::class, true],
        [AuthManagementAccess::class, false],
        [PasswordUpdater::class, false],
        [PrincipalAttributeMapper::class, false],
        [AccountConfirmation::class, false],
        [PrincipalSessionContainment::class, false],
        [RbacPrincipalAccess::class, false],
        [SystemMutationAccess::class, false],
        [AuthSubjectResolver::class, false],
        [AuthIdentifierResolver::class, false],
        [SuccessfulLoginMetadataRecorder::class, false],
        [AuthenticationEligibility::class, false],
        [ApiTokenManager::class, false],
        [ApiTokenAbilityProvider::class, false],
        [SocialIdentityProvider::class, false],
        [SocialSubjectResolver::class, false],
        [PasskeyCeremony::class, false],
        [InvitationSubjectResolver::class, false],
        [InvitationRegistrationMapper::class, false],
        [MembershipPrincipalResolver::class, false],
        [BrowserSession::class, true],
        [TenantAuthenticationSession::class, true],
        [AuthAuditContextProvider::class, true],
        [TenantAwareAuthActivityBridge::class, false],
        [InvitationRecipientProof::class, false],
    ];
}

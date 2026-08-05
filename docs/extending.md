# Extending

NVL Auth is usable without an application Auth module. Extension points exist
for business-specific relationships and policy, not to fill missing baseline
authentication behavior.

## User and model extension

Subclass `Nvl\Auth\Models\User` to add application relationships, scopes, casts,
or domain interfaces, then configure that subclass under
`features.principal_management.models.user`. Do not replace package identity
columns or the UUID key contract. The same pattern is available for Role,
Permission, and PersonalAccessToken through their feature `models` keys.

The model registry validates configured inheritance and every package Action
resolves the configured model, so API and direct PHP use remain aligned.

## Invitations

The default `PackageInvitationSubjectResolver` finds an existing package User by
invitation email or creates one from bounded registration input. Replace
`InvitationSubjectResolver` when acceptance must attach a tenant, require terms,
or use another provisioning policy. Invitation token, expiry, resend, revoke,
acceptance, RBAC payload, audit, Action, and route behavior remain package-owned.

## Delivery

Listen to the after-commit `AuthDeliveryRequested` event. It is the integration
boundary for `nvl/mail-notifications`, Laravel Notifications, SMS, push, or a
custom provider. The consumer maps the typed payload to channels/templates and
owns provider retry/tracking; Auth owns the secure invitation/challenge intent.

## Pipelines

```php
use Closure;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\ValueObjects\AuthPipelineContext;

final class EnsureTenantActive implements AuthPipelineStage
{
    public function handle(AuthPipelineContext $context, Closure $next): mixed
    {
        // Enforce one application policy using the bounded context.

        return $next($context);
    }
}
```

Stages may reject or enrich an existing use case. They must not bypass feature
admission, persist secrets from context, or open a competing transaction for the
same aggregate.

## RBAC catalogs and templates

Implement `PermissionCatalogProvider` and `RoleTemplateProvider` to add
application permissions and canonical roles. Keep the package providers in the
configured arrays so Auth API abilities remain available. Synchronization is
deterministic, transactional, and never deletes unrelated records.

The default management access contract authorizes the configured super-admin
role or delegates to Laravel Gate. Replace `AuthManagementAccess` only when the
application has another business authorization system.

## Passkeys, social providers, and tokens

- override `PasskeyCeremony` only for specialized attestation/metadata policy;
  Auth retains challenge, credential, counter, revocation, audit, Action, and
  route ownership;
- configure the bundled Socialite adapter or implement
  `SocialIdentityProvider`; `SocialSubjectResolver` controls linking/provisioning;
- use the built-in Sanctum manager or implement `ApiTokenManager`; implement
  `ApiTokenAbilityProvider` for subject-specific ability policy.

## Identity/session/audit ports

The defaults resolve package Users and Laravel browser sessions. Applications
with nonstandard lookup/session behavior may replace `AuthIdentifierResolver`,
`AuthSubjectResolver`, `BrowserSession`, or `AuthAuditContextProvider` while the
feature Actions remain the public business API.

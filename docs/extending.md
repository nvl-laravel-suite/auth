# Extending

NVL Auth is usable without an application Auth module. Extension points exist
for business-specific relationships and policy, not to fill missing baseline
authentication behavior.

## User and model extension

Subclass `Nvl\Auth\Models\User` to add application relationships, scopes, casts,
or domain interfaces, then configure that subclass under
`features.principal_management.models.user`. Map package principal semantics to
the subclass's physical schema through
`features.principal_management.settings.attributes`. The mapping covers ID,
name, email, verification, password, active state, locale/timezone,
profile/preferences metadata, login/lock state, remember token, timestamps, and
soft deletion. UUID principal identity remains required.

Eloquent attributes shadow relationships. If the subclass declares
`profile(): Relation`, map package profile metadata to a namespaced column such
as `auth_profile` and ensure the physical table has no `profile` column.
Doctor checks the actual principal table and rejects collisions. Role reserves
`priority`, `is_system`, and `metadata`; Permission reserves `group`,
`is_system`, and `metadata`. The same subclass pattern is available for Role,
Permission, and PersonalAccessToken through their feature `models` keys.

The model registry validates configured inheritance and every package Action
resolves the configured model, so API and direct PHP use remain aligned.

For an existing first-party principal table, use the manifest-driven adoption
bridge rather than an ad hoc copy. It validates UUIDs, normalized unique emails,
counts, hashes, extension columns, password-reset tokens, and declared host
foreign keys before writing. See [principal adoption](principal-adoption.md).

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

`RoleTemplateProvider::roles()` returns `RoleTemplate` values. Each template
may define its canonical role name, display name, description, system flag,
parent role, priority, permissions, and metadata. `ApplyRoleTemplateData` may
select another bounded target role name while retaining the template metadata
and permissions.

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

## Identity, session, metadata, and audit ports

The defaults resolve package Users and Laravel browser sessions. Applications
with nonstandard lookup/session behavior may replace `AuthIdentifierResolver`,
`AuthSubjectResolver`, `BrowserSession`, or `AuthAuditContextProvider` while the
feature Actions remain the public business API. Replace
`SuccessfulLoginMetadataRecorder` to map timestamps and request context onto a
host-owned principal schema. Replace `AuthAuditRecorder` to persist package
audit facts into an existing host audit store; the package Eloquent audit model
and `nvl_auth_audits` table are not required by that adapter.

RBAC-only consumers may replace `RbacPrincipalAccess` and configure an
independent RBAC principal model without enabling principal management.
Actorless bootstrap and domain workflows must pass `SystemMutationContext` and
be granted by a host `SystemMutationAccess` implementation; the package default
denies every such call. Replace `PrincipalSessionContainment` to compose
host-defined client sessions while preserving API-token, remember-token, and
Laravel database-session containment.

Password login emits `AuthenticationAttempted`, `AuthenticationRejected`,
`UserAuthenticated`, and `UserLoggedOut`. Attempt/rejection events include the
identifier but never the credential secret, so listeners must apply the host's
PII retention policy.

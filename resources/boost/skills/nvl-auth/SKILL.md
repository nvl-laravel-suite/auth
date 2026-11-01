---
name: nvl-auth
description: Use when integrating native authentication, registration, invitations, account security, sessions/tokens, memberships, RBAC or explicitly selected OAuth, TOTP and WebAuthn adapters with nvl/auth.
---

# NVL Auth Light

Auth targets PHP 8.4 and Laravel 13 with Core and native service families.
Consumers own HTTP/OAuth request acquisition, routes, sessions, cookies, response types and presentation.
Inject native services; retain explicit principals, context values, guards and validated arrays.

## Portable references

- [Installation](references/installation.md): providers, exact publish tags, migration ownership and optional engines.
- [Native API](references/api.md): every public signature, input/result type, contract and model capability.
- [Usage](references/usage.md): complete family selection, field contracts, proof flows and verified examples.

Read usage before choosing a security workflow and API before supplying native arguments.
Read installation for a new host, schema plan, adapter selection or reviewed adoption.
For proof and delivery reviews, consult [verification invariants](references/verification.md).
For security-code transport, consult [SMS delivery boundaries](references/sms-security-codes.md).
The local references remain complete after Laravel Boost publication.

## Select a complete service family

- `Authentication` / `AuthenticationSessions`: browser password login, proof finalization, MFA and logout.
- `AuthRegistration`, `AuthInvitations`, `AuthUsers`, `AuthUserReader`: provisioning and principal lifecycle.
- `AuthChallenges`, `AuthPasswords`, `AuthEmailVerification`, `AuthEmailChanges`: native delivery/proof workflows.
- `AuthReauthentication`, `AuthSecondFactor`, `AuthPasskeys`, `AuthSocialAuthentication`, `AuthSocialLinks`: account methods and step-up.
- `AuthTokens`, `AuthBrowserSessions`, `AuthRememberCredentials`, `AuthClients`: token/browser/client authority.
- `AuthMemberships`, `AuthRoles`, `AuthPermissions`, `AuthRbacReader`: owner membership and permissions.
- `AuthAccountSecurity`, `AuthAccountRecovery`, `AuthImpersonation`: method inventory, containment and delegated identity.
- `AuthAuditReader`, `AuthMaintenance`, native feature/doctor/adoption commands: observation and operations.

## Keep execution authority explicit

Management requires an actor and `AuthManagementAccess`; system mutations require
`SystemMutationContext` plus `SystemMutationAccess`. Defaults deny absent host decisions.
Scheduling `nvl:auth:prune` requires a host `SystemMutationAccess` policy approving
`nvl.auth.maintenance.prune`; its default denies even dry runs. Run outside a
database transaction. Retention uses one cutoff and `cleanup.batch_size` bounded
batches (default 250, range 1..1000), reauthorizes each batch, and retains completed
batches if a later batch fails. Retry safely; audits and security revisions remain.
Native Ownership requires reviewed adoption and live admission.
Owner intents and membership facts never become an implicit privileged execution scope.
Historical actor IDs and `AuthExecutionContext::facts` are attribution, not queue authority.
Select host principal mapping/identity adapters deliberately.

## Preserve mandatory proof and session rules

`verifyCredentials` proves credentials only; prefer complete login/loginWithToken operations.
Native proof/security-state schema is required even when optional methods are disabled.
Stateful success owns canonical eligibility, password, enrolled factor and guard/session checks.
Use pending-factor continuation for `second_factor_required`; retain the same server session.
Browser transitions and recent confirmation reject ambient source transactions.
Self-service security changes consume a purpose-bound recent grant inside their transaction.
Proof destinations, guard/session bindings, security revisions and one-use replay checks stay intact.
Never issue login authority from a raw principal or callback payload.

## Select optional engines and model extensions

Base User carries no Sanctum or Permission traits.
Enable/install only selected Sanctum, Spatie Permission, Socialite, Google2FA or WebAuthn adapters.
A scoped `SocialIdentityProviderFactory` must make a fresh provider/SDK driver per operation.
SDK-managed OAuth state and exact immutable social links remain authoritative.
Configure feature model subclasses before boot and retain native storage/casts/hooks.
RBAC catalog sync uses configured Permission storage; combined/template operations require
Role and Permission on one actual connection, with success audit after its outer commit.

## Native arrays, outputs and errors

Array schemas are operation-specific and closed; do not forward request payloads or drop nulls.
Proofs use `reveal()`; issued API tokens expose one-time `plainTextToken` separately from metadata.
Keep inspection redaction and each result type's serialization restrictions intact.
Return native models/collections/paginators or documented safe arrays through host resources.
Use `AuthException::errorCode` / `status` for host mapping; preserve neutral delivery responses.
The usage reference covers exact fields, continuation/step-up examples and operational commands.

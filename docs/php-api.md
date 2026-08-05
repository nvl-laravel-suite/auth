# PHP API

Actions are the supported PHP use-case API. Resolve them through Laravel's
container so configured adapters and pipelines are applied.

## Authentication and passwords

- `LoginAction`
- `LogoutAction`
- `EstablishAuthenticatedSessionAction`
- `RequestPasswordResetAction`
- `ResetPasswordAction`
- `ConfirmPasswordAction`
- `UpdatePasswordAction`
- `RequestEmailVerificationAction`
- `VerifyEmailAction`

## Challenges and invitations

- `RequestMagicLinkAction`, `ConsumeMagicLinkAction`
- `RequestSecurityCodeAction`, `VerifySecurityCodeAction`
- lower-level `IssueChallengeAction`, `ConsumeChallengeAction`
- `CreateInvitationAction`, `PreviewInvitationAction`, `AcceptInvitationAction`
- `ResendInvitationAction`, `RevokeInvitationAction`, `ListInvitationsAction`

Issuance Results redact plaintext secrets from debug output. Callers must avoid
logging or caching the returned secret.

## Authenticators

- TOTP: start, confirm, verify, revoke
- passkeys: begin/finish registration, begin/finish authentication, revoke
- recovery codes: regenerate, consume, revoke
- social identities: start/complete authorization, link, revoke

## Clients and sessions

- client create/list/show/update/activate/deactivate/delete/start
- client-session record/touch/end

Client-session Actions correlate a host Laravel session ID by hash. They never
authenticate a request.

## API tokens and RBAC

- API token list/create/update/rotate/revoke/revoke-all
- atomic complete RBAC synchronization, plus granular permission-catalog and
  role-template synchronization Actions

Provider adapters remain authoritative. The package does not expose a duplicate
token or role model. The Sanctum adapter exposes only tokens carrying its
configured package namespace.

## Audit and cleanup

- `ListAuthAuditsAction`, `ShowAuthAuditAction`
- `PruneAuthStateAction`

`AuthAuditRecorder` is an internal reusable service used after successful or
failed package transitions. When audit is enabled it may record containment work
even while functional ingress is off.

## Contracts

Public extension contracts are in `Nvl\Auth\Contracts`:

- subject-reference, login-identifier, invitation, and social resolvers;
- password updater;
- passkey ceremony;
- social identity and API-token provider adapters;
- API-token ability provider;
- permission and role catalog providers;
- management access;
- browser-session and audit-context adapters;
- pipeline stage.

## Admission

Use `FeatureGate::allows(AuthFeature, FeatureOperation)` for UI/capability checks
and `assertAllowed` for an explicit failure. Transport input never decides
feature availability. `AuthException` provides a stable error code and HTTP
status for package routes.

## Events

- `AuthDeliveryRequested(AuthDeliveryRequest)`
- `AuthAuditRecorded(auditId)`
- `UserAuthenticated(SubjectReference)`
- `UserLoggedOut(?SubjectReference)`

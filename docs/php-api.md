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
- `DeleteOwnAccountAction`

`AuthenticationEligibility` is invoked after subject resolution and before
credential, passwordless, social, or password-reset success. Replace it under
`features.authentication.services.eligibility`. Sparse profile writes use
`UpdateProfileData::toArray()` semantics; changing email additionally requires
the replaceable `AccountConfirmation`, clears verification atomically, and
requests a fresh verification delivery.

## Challenges and invitations

- `RequestMagicLinkAction`, `ConsumeMagicLinkAction`
- `RequestSecurityCodeAction`, `VerifySecurityCodeAction`
- lower-level `IssueChallengeAction`, `ConsumeChallengeAction`,
  `ConsumeChallengeByIdAction`
- `CreateInvitationAction`, `PreviewInvitationAction`, `AcceptInvitationAction`
- `RegisterInvitationAction`, `ResendInvitationAction`,
  `RevokeInvitationAction`, `ListInvitationsAction`

Magic links contain one opaque token and one numeric fallback code for the same
single-use challenge. Token-only callbacks carry `challengeId` and the chosen
credential; legacy recipient-bound consumption remains supported.

Pass trusted `InvitationIssuanceContext` from host orchestration for explicitly
authorized actorless issuance, a bounded expiry override, or a post-accept
return path. Public request input must never construct this context.
`InvitationIndexQueryData` supports exact normalized recipient, type, purpose,
lifecycle, expiry, and exact host-context filters. Recipient substring search is
intentionally unavailable because recipients are encrypted at rest.
The built-in registration mapper handles password registration. A host mapper
may admit `registrationMethod=social` and consume only bounded `extensions`
after its provider proof has succeeded; the atomic Action and acceptance hooks
remain unchanged.

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

The `AuthAuditRecorder` contract is used after successful or failed package
transitions. Configure a host implementation under
`features.audit.services.recorder` to retain an existing audit schema. When
audit is enabled it may record containment work even while functional ingress
is off.

## Contracts

Public extension contracts are in `Nvl\Auth\Contracts`:

- subject-reference, login-identifier, invitation, and social resolvers;
- authentication eligibility, account confirmation, and invitation
  registration mapping;
- password updater;
- passkey ceremony;
- social identity and API-token provider adapters;
- API-token ability provider;
- permission and role catalog providers;
- management access;
- browser-session, successful-login metadata, audit-recorder, and audit-context adapters;
- pipeline stage.

## Admission

Use `FeatureGate::allows(AuthFeature, FeatureOperation)` for UI/capability checks
and `assertAllowed` for an explicit failure. Transport input never decides
feature availability. `AuthException` provides a stable error code and HTTP
status for package routes.

## Events

- `AuthDeliveryRequested(AuthDeliveryRequest)`
- `AuthAuditRecorded(auditId)`
- `AuthenticationAttempted(identifierName, identifier)`
- `AuthenticationRejected(identifierName, identifier, reason, ?SubjectReference)`
- `UserAuthenticated(SubjectReference)`
- `UserLoggedOut(?SubjectReference)`

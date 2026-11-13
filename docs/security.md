# Security

## Secrets and identifiers

Opaque bearer values are generated with cryptographic randomness and stored only
as purpose-separated HMAC-SHA256 indexes. Numeric codes use `random_int` and are
also purpose-separated by message type and recipient hash.

Laravel encrypted casts protect invitation recipients, TOTP secrets, passkey
material, social identity claims, client-session context, challenge adapter
state, and audit context. `APP_KEY` is therefore installation-critical.

Do not change `APP_KEY` or the operational connection without migrating retained
rows. Do not log service results containing issuance secrets.

## Authentication and enumeration

- Login returns one neutral credential failure. Stateful credential login enforces enrolled TOTP or recovery proof before guard authentication. Its opaque server-session continuation uses an existing locked Challenge row, expires after five minutes, shares a five-attempt budget across stale session snapshots, binds the current password hash through a purpose-separated HMAC, and is consumed before the success pipeline. It never retains the password.
- Native credential and passwordless session paths reload persisted eligibility across login pipelines and reject principal substitution. Raw token issuance supplies canonical current actors to configured eligibility and ability providers; non-Eloquent adapters retain their external identity freshness contract.
- Password-reset request does not reveal whether the identifier matched or was
  rejected by the configured `AuthenticationEligibility` policy. Ineligible
  subjects receive no token or delivery, and reset consumption checks the same
  policy before changing credentials.
- Public magic-link requests resolve through the configured user provider, emit no
  delivery for unknown identifiers, and return a neutral service outcome for consumer transport mapping.
- Consumers own timing protection around account-bound magic-link, security-code
  and password-reset endpoints. Apply a minimum-duration Laravel Timebox without
  early return and queue delivery listeners; a timing floor alone does not hide
  host work that exceeds it. Native services do not impose an HTTP timing floor.
- Challenges bind message type, purpose, normalized recipient, and secret.
  Compound magic links store independently purpose-separated hashes for their
  link token and fallback code; consuming either credential consumes both.
  Direct callbacks use the challenge UUID and never scan active rows.
- A database uniqueness key prevents concurrent issuance from leaving multiple
  active message challenges for the same recipient, type, and purpose.
- Wrong challenge/passkey attempts are committed before a neutral error returns.
- Consumed, revoked, expired, and attempt-exhausted state cannot be reused.
- Laravel session IDs regenerate only after eligibility and login-pipeline
  acceptance. Successful-login metadata is recorded after those checks.
- Self-service account deletion requires the configured confirmation policy,
  revokes all subject API tokens, logs out the guard, invalidates the browser
  session, and rotates its CSRF token.
- Sensitive operations require the native recent-authentication grant, bound to
  the current principal and proof context. Laravel password-confirmed session
  timestamps are presentation state and do not authorize these operations.
- Consumers must make authentication responses non-cacheable and suppress referrer
  leakage. The headless package registers no HTTP routes or response middleware.

Principal Eloquent fillable fields are a storage mechanism, not an authorization policy. Do not pass request arrays directly to `User::create`, `fill` or `update`; use the native principal services and their explicit field/policy boundaries for verification, activation, lock and credential state. Host model extensions must validate their own trusted mutation inputs as well.

## Passkeys

The built-in `WebauthnPasskeyCeremony` performs complete WebAuthn verification:
challenge, ceremony type, exact allowed origin, RP ID hash, assertion signature,
user presence/verification, `none` attestation, allowed credential/user handle,
algorithm, counter, backup bits, and credential parsing. Auth supplies the stored
COSE public key, user handle, counter, and backup state, then independently
enforces counter regression and backup-eligibility invariants transactionally.
Unexpected ceremony-adapter failures are retained as previous exceptions for
PHP diagnostics but normalized to stable package errors. Consumers must map those
errors to neutral HTTP responses.
Browser responses, adapter state, and returned option documents are bounded
before persistence or response serialization. User verification is required by
default, and the per-subject credential limit defaults to 20.

`AuthPasskeys::beginAuthentication($subject)` returns that subject's credential
identifiers in `allowCredentials`. Pass a subject only after the host has already
authenticated it (second factor or reauthentication); for a sign-in page pass no
subject, so the discoverable-credential options disclose nothing about an account.
A signature counter that stops advancing, including a reset to zero after a
non-zero value, is refused as `passkey_counter_regression`.

Doctor requires the built-in or configured ceremony implementation to resolve,
plus a configured subject resolver and valid RP, origin, timeout, resident-key, and
user-verification policy before a passkey-enabled deployment is ready.

## Social identities

Provider identity is a configured connection alias and immutable provider ID. A
validated, fixed issuer can be supplied as provenance; existing links reject issuer
changes, so changing a connection realm requires an explicit migration. Email is
an optional claim, not ownership authority. An authenticated subject can link a
proved provider identity without verified email. For an unauthenticated callback,
an active immutable link can resolve its subject without email; unknown identities
return a server-held registration continuation. Native explicit registration requires provider-verified email provenance or a separate bounded local mailbox proof. No callback may resolve or merge a principal by email.

The Socialite adapter recognizes Google's boolean `email_verified` userinfo claim.
For the unmodified GitHub SDK driver, it recognizes the SDK's verified-primary
email endpoint only when `user:email` is in the effective driver scopes. Other
drivers fail closed unless the host explicitly supplies a
`SocialiteEmailVerification` policy backed by that provider's proof. The host is
responsible for matching its policy to the driver and its returned claims. OAuth
protocol parameters are reserved. No access or refresh tokens enter the identity.

## API tokens and RBAC

The API-token ability provider must return the maximum abilities allowed for the
current subject. The default static catalog is empty (deny by default). The
Sanctum adapter only mutates subject-owned tokens carrying its configured
package namespace. Other Sanctum tokens remain outside package list,
update, rotation, and revocation operations.

Invitation role/permission payloads require the RBAC feature and a configured model
using Spatie `HasRoles`. Management routes additionally require
`AuthManagementAccess`; route enablement is not authorization.
Invitation grants also require Auth principal, role, and permission storage
to share one connection so the acceptance transaction cannot partially commit.
Public registration resolves or creates the principal, applies RBAC, consumes
the invitation, and runs acceptance hooks inside that one transaction.

Actorless RBAC and principal lifecycle operations require a bounded
`SystemMutationContext` and host `SystemMutationAccess` approval. The default
policy denies every system mutation. Reasons and correlation identifiers are
included in package audits and events; an optional real actor remains optional
and is never fabricated.

Disabling, deleting, restoring, and equivalent bulk containment transitions use
`PrincipalSessionContainment` inside the lifecycle transaction. The Laravel
adapter revokes package Sanctum tokens, rotates the remember credential, and,
when the database session driver is active, deletes every row for the principal.
Hosts replacing the adapter must preserve these guarantees while adding their
own client-session stores.

Invitation recipient and host-context lookup are exact HMAC blind-index
matches. Substring recipient search is deliberately unsupported; decrypting and
scanning rows in memory is not a safe package fallback.

## Delivery

`AuthDeliveryRequested` may contain a one-time secret. Use a queued listener with
encrypted/secured transport appropriate to the host, deduplicate `messageId`,
recheck feature admission, reject expired payloads, and prevent observability
systems from capturing payload values.
The value object rejects feature/message pairs outside the package-owned map.

## Native owner boundaries

Canonical owners and one-use authentication intents select native owner scope; caller IDs alone never grant admission. Global principals and credentials remain global. RBAC assignments, invitations and package tokens must satisfy current owner/membership rules. OAuth state remains owned by the SDK, and the separate owner intent is single-use, purpose/provider/session-bound. Audit facts and queued delivery capture native immutable ownership context and revalidate at worker entry.

## Disablement

Disabling a feature blocks normal read/enroll/issue/use/update admission and
closes new service admission. Data remains. Revoke retained credentials
before disablement if later re-enablement must not reactivate them. Revoke and
cleanup operations remain admitted as containment operations.

New passwords use the configured `PasswordPolicy` (minimum 12 characters by default), bounded input and the selected bcrypt engine's 72-byte limit. Existing hashes remain valid without meeting the new policy. Password changes rotate the native remember token; they do not delete unrelated application tokens or database sessions. Future revision and managed-session enforcement is separate.

Atomic password reset requires an Eloquent principal and Laravel's database token repository on the same actual connection as the principal and audit storage. Non-Eloquent or nontransactional external stores need a host-owned flow; they are not covered by this atomicity guarantee. Reset events are emitted after the outer commit.

## Principal security revisions

Native password changes/resets, administrative credential reset, TOTP enrollment/restart/revocation, recovery replacement/revocation, passkey enrollment/revocation, new social links/revocation, email changes and principal disable/delete/restore advance a central monotonic revision. Initial principal creation starts at 1. Ordinary profile changes and idempotent revocations do not advance it. Revision, credentials, native challenge invalidation and committed facts obey enclosing transaction rollback. Consumers never submit a revision as proof or mutate this internal store.

Mutations lock canonical principals in stable order, their security states, native challenges, then credentials. Passkey provider verification runs before these locks and the final write revalidates the stored ceremony, credential and revision. PostgreSQL uses current locking reads for unique state creation and reload.

Current invalidation covers subject-bound `passkey_authentication`, `passkey_registration` and `credential_second_factor` challenges across owners. Generic magic-link/security-code business purposes retain their own lifecycle; they are not current-revision native authentication proofs. Remember tokens rotate on security changes. Password mutations revoke every package-managed API token across native owners while preserving unrelated token namespaces.


## Native proof provenance and assurance

Every native login method enforces required enrolled MFA independently of optional method flags. Password/email/ordinary social/non-UV passkey evidence is single factor; native verified passkey UV satisfies MFA. Social profile amr/acr claims never grant MFA. Enrolled credentials remain central facts under ambient owner scopes; owner access remains separate from identity proof.

Native email/passkey/social initiation captures trusted destination and browser/guard context before redemption. Generic business challenge APIs cannot mint native login evidence. Passwords capture credential fingerprint and revision before provider verification, then compare canonical persistence under lock before rehash/issuance. Social provider I/O precedes native locks, including within a host transaction. Proof completion reconstructs encrypted native evidence under canonical locks and rechecks persistence around hooks, even when a consumer resolver supplies stale models.

Proofs use purpose-separated HMAC indexes, encrypted facts, 300-second lifetime, five shared failed factor attempts and one-use final consumption. Token proofs bind a client namespace and per-flow nonce without browser state. Issued proof secrets redact debug output and reject serialization. No supported public generic issuer or bare-principal session establishment remains.

Account method inventory is a safe projection of usable native credentials. Removals lock the canonical principal and recheck credential ownership from storage. The native policy always preserves a primary method; recovery codes never count as primary. Bind `AccountAuthenticationPolicy` for additional business requirements, including organization-mandated factors. Explicit factor removal requires native recent authentication with the enrolled factor; the default permits a deliberate MFA opt-out after that proof. Consumer policy can prohibit it. Listen for committed `AccountSecurityChanged` facts to send security notifications.

Passwordless accounts use `AuthPasswords::setInitial` with native PasswordChange recent proof from a linked social identity or user-verified passkey. An existing password is rejected under lock. `remove` preserves a usable primary and enforces consumer policy. `AuthAccountRecovery::recover` requires explicit human/SystemMutationContext authority and the separate users.recover ability. It accepts a bounded reason and selected native credential IDs, preserves a usable primary and performs complete managed containment; false revokeSessions/revokeTokens instructions are rejected. Support identity proof remains host policy. Recovery cannot verify a mailbox, activate an account or grant roles. Consumers deliver committed AccountSecurityChanged notifications.

### Impersonation

Impersonation defaults off and its access policy denies by default. Enable it only with managed admission, audit storage and a consumer `ImpersonationAccess`. Start requires an original browser and ImpersonationStart recent grant, a reason (1–500 characters), and 60–1800 seconds (default 900). The target must be active and admitted to the captured current owner; payload cannot select owner or actor. Every request rechecks both revisions, permissions, owner membership, browser/guard and expiry.

Use `LaravelImpersonation::start/stop` for browser binding and CSRF rotation, and `run`/consumer middleware for the target overlay. The Laravel session/recaller identity remains the original human. Start/stop POST endpoints require CSRF/auth/throttling and execute outside the overlay. An admitted callback temporarily uses the target, then restores guard, owner principal and permission caches after success or exception. Unsafe restoration logs out. No target token or remember cookie is created. Native auth mutations, token issuance, recovery, RBAC/membership administration and nested impersonation are denied during an overlay before host policy. Stop requires the matching original session, without another fresh grant. Forced revocation has a separate management/system ability.

A transport failure after durable grant creation compensates by stopping the grant and revoking the browser before logout; retry requires fresh authentication. Pre-grant denials roll back grant consumption and successful facts. Native audit actor columns retain the original human; reserved effective_subject_type/effective_subject_id/impersonation_id metadata comes from verified scope and rejects caller overrides. Deferred native writes capture immutable attribution at source. Consumer audit adapters read `AuthExecutionContext::facts()` and preserve those facts at their source boundary. The execution context cannot be serialized into jobs; consumers must separately authorize background actor context, rather than capturing the browser overlay.

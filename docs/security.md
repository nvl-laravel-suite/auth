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
  delivery for unknown identifiers, and return the same neutral HTTP response.
- Account-bound magic-link, security-code and password-reset HTTP requests use a
  200 ms minimum Laravel Timebox without early return. Queue delivery listeners;
  host work exceeding that floor can still expose account-dependent timing.
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
- Password confirmation uses Laravel's standard session timestamp.
- Every package HTTP response is non-cacheable and suppresses referrer leakage.

## Passkeys

The built-in `WebauthnPasskeyCeremony` performs complete WebAuthn verification:
challenge, ceremony type, exact allowed origin, RP ID hash, assertion signature,
user presence/verification, `none` attestation, allowed credential/user handle,
algorithm, counter, backup bits, and credential parsing. Auth supplies the stored
COSE public key, user handle, counter, and backup state, then independently
enforces counter regression and backup-eligibility invariants transactionally.
Unexpected ceremony-adapter failures are retained as previous exceptions for
PHP diagnostics but normalized to stable, neutral package errors over HTTP.
Browser responses, adapter state, and returned option documents are bounded
before persistence or response serialization. User verification is required by
default, and the per-subject credential limit defaults to 20.

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
require verified email before the configured `SocialSubjectResolver` is called.
Custom resolvers matching by email must inspect the verification and provenance.

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

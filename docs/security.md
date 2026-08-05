# Security

## Secrets and identifiers

Opaque bearer values are generated with cryptographic randomness and stored only
as purpose-separated HMAC-SHA256 indexes. Numeric codes use `random_int` and are
also purpose-separated by message type and recipient hash.

Laravel encrypted casts protect invitation recipients, TOTP secrets, passkey
material, social identity claims, client-session context, challenge adapter
state, and audit context. `APP_KEY` is therefore installation-critical.

Do not change `APP_KEY` or the operational connection without migrating retained
rows. Do not log Action result objects containing issuance secrets.

## Authentication and enumeration

- Login returns one neutral credential failure.
- Password-reset request does not reveal whether the identifier matched.
- Public magic-link requests resolve through the configured user provider, emit no
  delivery for unknown identifiers, and return the same neutral HTTP response.
- Challenges bind message type, purpose, normalized recipient, and secret.
- A database uniqueness key prevents concurrent issuance from leaving multiple
  active message challenges for the same recipient, type, and purpose.
- Wrong challenge/passkey attempts are committed before a neutral error returns.
- Consumed, revoked, expired, and attempt-exhausted state cannot be reused.
- Laravel session IDs regenerate after login and invalidate on logout.
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

Provider identity is `(provider, immutable provider user ID)`. Email is a claim,
not ownership authority. The configured `SocialSubjectResolver` decides whether to
resolve, provision, or reject a subject. Auth does not persist OAuth access or
refresh tokens and does not auto-link by email.

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

## Delivery

`AuthDeliveryRequested` may contain a one-time secret. Use a queued listener with
encrypted/secured transport appropriate to the host, deduplicate `messageId`,
recheck feature admission, reject expired payloads, and prevent observability
systems from capturing payload values.

## Disablement

Disabling a feature blocks normal read/enroll/issue/use/update admission and
removes its routes on cache rebuild. Data remains. Revoke retained credentials
before disablement if later re-enablement must not reactivate them. Revoke and
cleanup Actions remain admitted as containment operations.

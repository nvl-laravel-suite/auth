# Flows

## Password login

1. `LoginAction` gates authentication, password, and sessions.
2. Laravel's configured stateful guard attempts credentials.
3. The `login` pipeline receives the resolved subject and may reject it.
4. Laravel regenerates the session ID.
5. Auth records an optional audit and publishes `UserAuthenticated`.

## Password reset

`RequestPasswordResetAction` uses Laravel Password Broker over
`nvl_auth_password_reset_tokens`, then emits `AuthDeliveryRequested`.
`ResetPasswordAction` returns the token to the broker, delegates the configured
User mutation to `PasswordUpdater`, and publishes Laravel's `PasswordReset`
event. Auth owns reset-token persistence but no delivery table.

## Magic links and security codes

Issuance normalizes the recipient, revokes earlier active challenges for the
same type/purpose/recipient, persists a hash, and publishes the plaintext secret
only in the delivery event. A database uniqueness key closes concurrent-issuance
races. Consumption locks the row, commits capped wrong-attempt counters, and
consumes a valid row once.

A subject-bound magic link may establish a Laravel session through
`AuthSubjectResolver`. Generic security-code verification returns the consumed
challenge so host policy can decide what it proves.

## Invitations

Management creates a simple expiring invitation and receives the plaintext token
once. Public acceptance previews it, asks `InvitationSubjectResolver` to resolve
or create a configured package principal, consumes the invitation
transactionally, and applies
optional Spatie roles/permissions. Resend rotates the token; revoke is idempotent.

## TOTP and recovery codes

TOTP starts with an encrypted secret and returns the provisioning URI. Confirm
requires a valid code. Later verification locks the credential and advances a
stored timestep so the same code cannot replay.

Recovery-code regeneration revokes prior unused codes and returns a new plaintext
batch once. Each row stores one hash and is consumed independently.

## Passkeys

The built-in WebAuthn adapter creates RP-bound browser options and encrypted
ceremony state. Registration validates challenge, type, origin, RP ID hash,
presence, verification, algorithm, credential identity, and `none` attestation,
then returns credential material for encrypted package storage. Authentication
extracts the credential ID, Auth loads/locks it, and the adapter validates the
real assertion signature, user handle, counter, backup bits, and configured
policy. Auth advances signature/backup state and consumes the ceremony.
Documents and browser responses are bounded, user verification is required by
default, and per-subject credential counts are configurable. A host may replace
the ceremony contract without replacing the package lifecycle.

## Social identities

The provider adapter builds an allowlisted authorization redirect and acquires
verified callback claims. Auth hashes/encrypts the immutable provider identity,
never stores OAuth tokens, and asks the host resolver for the subject. Account
linking can explicitly bind a provider identity to the current subject.

## API tokens

Actions gate and apply the subject-aware ability catalog, then call
`ApiTokenManager`. The Sanctum adapter lists, creates, updates, rotates, and
revokes only namespaced package-managed rows in
`nvl_auth_personal_access_tokens`. Rotation creates the replacement and removes
the old token on the package/Sanctum connection transaction; unrelated Sanctum
tokens are never included.

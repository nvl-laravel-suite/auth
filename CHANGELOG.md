# Changelog

All notable changes to `nvl/auth` are documented here.

## Unreleased

## 1.0.1 - 2026-08-09

### Changed

- Made disabled provider registration passive for host authentication,
  authorization, Sanctum, password-broker, and migration state.
- Added configurable audit persistence and successful-login metadata contracts.
- Added authentication attempt and rejection events, including request-context
  metadata for successful logins.
- Documented the physical schema contract retained by configurable Auth models.
- Rebuilt the package around sixteen independently enabled authentication
  features and one canonical feature/route manifest.
- Added the concrete, extensible package User model with profile, search,
  suggestions, CRUD, restore, enable/disable, bulk operations, and access
  assignment Actions and optional JSON APIs.
- Added package-owned Spatie-compatible Role/Permission models and UUID pivots,
  including CRUD, cloning, hierarchy, templates, analytics, and synchronization.
- Added package-owned Sanctum PersonalAccessToken and password-reset-token
  tables while retaining Sanctum and Laravel provider behavior.
- Namespaced the complete 17-table schema with the `nvl_auth_` prefix.
- Replaced notification and delivery infrastructure with the after-commit
  `AuthDeliveryRequested` event and typed `AuthDeliveryRequest` payload.
- Added fail-closed optional adapters for Sanctum and Socialite, plus a
  maintained built-in WebAuthn passkey ceremony that remains replaceable.
- Added first-party client allowlists and Laravel-session correlation without a
  shadow session implementation.
- Added named host pipelines, route/surface flags, stale-cache middleware,
  readiness diagnostics, feature inventory, and explicit pruning.
- Removed the former delivery, outbox, scheduler, checkpoint, recovery saga,
  principal projection, shadow session, and shadow token architecture.
- Removed unused hard dependencies on NVL data/support, Spatie Data/TypeScript,
  and cron; retained the maintained WebAuthn stack required by built-in passkeys.
- Added Laravel-native password confirmation and transport-independent browser
  session/audit-context ports.
- Added route-only dependency admission so login and passwordless callbacks are
  never registered without the features required to complete their session.
- Added Laravel-native password confirmation, complete client detail/status and
  audit-detail management APIs, transport-independent browser/audit ports, and
  subject-bound public magic-link authentication.
- Made RBAC catalog/template synchronization atomic while retaining granular
  synchronization Actions and enforcing one connection for invitation grants.
- Namespaced Sanctum token names so package operations cannot list, mutate,
  rotate, or revoke host-created personal access tokens.

### Security

- Challenge failures now commit bounded attempt counters before returning.
- Passkey verification receives the stored public key, user handle, signature
  counter, and backup state from package persistence.
- Invitation recipients, TOTP secrets, passkey material, social claims,
  client-session context, and audit context are encrypted at rest.
- Bearer challenges, invitation tokens, recovery codes, client session IDs, and
  provider identifiers use purpose-separated hashes.
- Package HTTP responses now use no-store, no-referrer, and MIME-sniffing
  protection headers; passkey adapter exceptions are normalized at the boundary.
- API-token abilities now deny by default; social-provider failures are neutral;
  provider redirect URLs, audit/delivery payloads, client-session metadata, and
  WebAuthn inputs are bounded.
- Database uniqueness keys enforce one active invitation and one active message
  challenge for their ownership keys; challenge attempts are capped and client
  session correlations cannot be resurrected after termination.
- Passkeys require user verification by default, enforce configurable credential
  limits, validate RP/origin and resident-key policy, use opaque HMAC-derived
  user handles, and use database-portable encrypted storage widths.

### Compatibility

- This is an intentional pre-1.0 configuration and schema break. No compatibility
  shim is provided for the previous overbuilt configuration tree.

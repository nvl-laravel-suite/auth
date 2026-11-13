# Changelog


All notable changes to `nvl/auth` are documented here.

## [Unreleased]

## [7.0.4] - 2026-11-13

### Fixed

- Compare `SubjectReference` and `OwnerReference` identities strictly across authentication, proofs, sessions, challenges, passkeys, tokens, impersonation, and invitations so numeric-looking string identifiers never coerce.
- Avoid clearing shared permission caches on every owner scope entry, guard disabled RBAC and API-token features cleanly, resolve PostgreSQL active schemas via `coalesce(current_schema(), 'public')`, and map concurrent social-link and invitation unique races to `409` responses without poisoning transactions.

<!-- NVL GENERATED CHANGES START -->
### Changed

- harden package runtime safety, PostgreSQL portability and test performance
<!-- NVL GENERATED CHANGES END -->

## [7.0.3] - 2026-11-11

### Fixed

- `NVL_AUTH_RETENTION_DAYS` is read as an integer, so setting it no longer makes `nvl:auth:prune` fail with an invalid-configuration error; a non-integer value still fails closed. Hosts that published the full configuration should apply the same `filter_var(..., FILTER_VALIDATE_INT)` read.
- Security codes and magic-link fallback codes are redrawn when they collide with a retained challenge for the same recipient, instead of surfacing a database unique-constraint error; repeated collisions report `challenge_issue_conflict` (409).
- Password-reset deliveries carry the expiry Laravel's password broker enforces (`auth.passwords.<broker>.expire`). `features.password.settings.reset_ttl_minutes` never changed the token lifetime, is no longer read and is removed from the default configuration; `nvl:auth:doctor` warns only while a host still sets it.
- Role and permission create, update, delete, duplicate and template mutations flush the Spatie permission cache after their transaction, so a concurrent check can no longer leave a revoked grant cached.
- API-token namespaces containing `_` match their exact prefix, so listing or revoking managed tokens no longer touches host tokens whose names merely resemble the namespace.
- A pending two-factor login survives `session.serialization=json`; the continuation context is stored as plain data.
- Pending email changes expire after `features.email_verification.settings.ttl_minutes` instead of a fixed 60 minutes.
- Password login spends one password hash when the identifier is unknown or the account has no password, so response time no longer reveals whether an account exists; the failure stays `credentials_invalid` (422).
- Password-reset requests honour `auth.passwords.<broker>.throttle`: a repeat request inside the window creates no token and sends nothing, returns as before, and is audited as `password.reset_rejected` with reason `password_reset_throttled`.
- Role parent changes lock the guard's roles and re-read the ancestor chain inside the transaction, so two concurrent updates can no longer commit a hierarchy cycle.
- Duplicate-key errors are translated by the unique index actually violated, read from the configured table, on SQLite and PostgreSQL. Registration, invitation registration and email-change completion translate only their own identity uniqueness violation (`registration_unavailable`, `invitation_principal_conflict`, invalid change); any other constraint failure now surfaces as itself instead of as that conflict.
- API-token namespaces are matched case-sensitively. A host token named `ACME:…` is outside namespace `acme`.
- The unread configuration keys `features.principal_management.settings.use_as_auth_model` and `features.rbac.settings.use_package_storage` are removed from the default and published configuration.
- One login runs each of its schema catalog probes once instead of repeating the TOTP, challenge and managed-session probes up to twelve times.
- With managed sessions, the browser that performs its own security action (TOTP, recovery codes, passkeys, social links, password, email change) stays signed in; every other browser and every remember credential still ends.
- Rolling back the identity migration no longer drops a configured host table that the migration adopted instead of creating.
- `AuthInvitations::revoke` accepts a `SystemMutationContext` like `create` and `resend`, and is refused while impersonating.
- Passkey assertions reporting a zero signature counter after a non-zero one are rejected instead of resetting the stored counter.
- A principal's unexpired authentication proofs share one five-attempt TOTP/recovery budget, so a new password proof no longer grants new factor guesses.
- The Socialite adapter refuses OAuth2 drivers that issue no SDK-managed `state`.
- Membership enrolment that grants or replaces access requires `nvl.auth.memberships.manageAccess`.
- Revoking an owner membership ends its owner administration, and ownership transfer requires an active recipient.
- Invitations carrying roles or permissions require `nvl.auth.users.manageAccess` when issued and a still-authorised issuer when accepted.
- Impersonation revocation, expiry on restart and failed-transition stops are audited with both principals.
- Management searches match `%` and `_` literally, and legacy role and permission page filters are length-bounded.
- Email-identity adoption streams only the identity columns instead of loading every principal.
- `nvl:auth:configuration` reports drift as unavailable when inspection fails instead of reporting no findings.

<!-- NVL GENERATED CHANGES START -->
### Changed

- harden credentials, RBAC cache, deliveries and schema probes
<!-- NVL GENERATED CHANGES END -->

## [7.0.2] - 2026-11-10

### Changed

- Remove the obsolete Spatie Laravel Data development dependency. Authentication test adapters now use native Laravel validation and explicit consumer projections while retaining the optional authentication integrations.

<!-- NVL GENERATED CHANGES START -->
### Changed

- retire Spatie Data test dependency
<!-- NVL GENERATED CHANGES END -->

## [7.0.1] - 2026-11-09

### Changed

- Refresh the inherited Ownership deletion API reference for ordinary models and native pivots.

<!-- NVL GENERATED CHANGES START -->
### Changed

- refresh inherited ownership deletion contracts
<!-- NVL GENERATED CHANGES END -->

## [7.0.0] - 2026-11-03

- Adopt the reviewed NVL 7 family for PHP 8.4+ and Laravel 13, with compatible required and optional NVL peers. Review the package upgrade guide before deployment.

### Changed

- Align NVL peers and consumer contracts on the coordinated 7.x line. Review [UPGRADING.md](UPGRADING.md) for adoption and application-owned integration requirements.

### Fixed

- Prune retained terminal state in bounded batches with one cutoff, fresh authority and repeated ownership/terminal predicates; explain the default-denied scheduling policy in command help.
- Reject malformed native credential identifiers with a domain denial and preserve last-method protection when different UUID spellings address the same stored credential.
- Preserve UTC instants in PostgreSQL timestamp storage and source-aware expiry, retry, lock, and retention predicates, including framework-managed timestamps.

## [6.1.0] - 2026-10-23

<!-- NVL GENERATED CHANGES START -->
### Changed

- expose safe host APIs and harden package boundaries
<!-- NVL GENERATED CHANGES END -->

## [6.0.0] - 2026-10-20

### Release fixes

- Centralize native membership and authentication-intent table names and classify the ownership opt-in in advanced configuration without changing storage identities.

### Fixed

- Export the nullable native membership owner reference as its exact scalar TypeScript shape without a frontend dependency in the neutral Core identity type.

### Changed

- Integrate native owner admission and captured delivery, proof and permission-storage boundaries with explicit host Auth adoption. Drain or expire legacy pending proofs before native activation; keep host principal keys, role policies and Spatie opt-in intact.
- Align required/development NVL peers on `^6.0`, optional peer conflicts on major 6, and `dev-main` on `6.x-dev`. Review [UPGRADING.md](UPGRADING.md) before rollout.

## [5.0.1] - 2026-10-08

### Changed

- Correct published-family verification and adoption guidance for local Dagger CI; runtime contracts are unchanged.


## [5.0.0] - 2026-10-08

### Added

- Focused execute contracts for supported Auth workflows, with exact existing signatures, generic results and sensitive parameter attributes; host services can substitute interfaces while concrete Actions retain their constructors and behavior.

### Changed

- Register focused defaults transiently with `bindIf` and existing public extension defaults conditionally with their native lifetimes. Preserve host membership bindings while replacing only Core's exact native unshared disabled fallback when Auth membership enforcement is enabled.
- Classify the supported consumer PHP surface with explicit source annotations and restrict package model handles to declared identity and in-memory read fields; preserve existing workflow behavior and concrete signatures.
- Adopt lockstep major 5 with required and development NVL peer floors of `^5.0`.
- Default HTTP ingress, principal-model adoption, password-broker storage adoption and Spatie storage adoption to off.
- Require explicit host targets; preserve host teams and use scoped audit services and one permission readiness hook.
- Allow Spatie's provider-boot registrar wiring without probing adopted tables; subsequent runtime resolution still requires ready storage.
- Invalidate scoped permission readiness after Auth tenant-storage activation, so new roles immediately use the activated tenant ownership.
- Review [UPGRADING.md](UPGRADING.md) before adopting the new names and infrastructure boundaries.

## [2.2.1] - 2026-09-26

### Documentation

- Clarify public support, contribution, and private security reporting paths.

## [2.2.0] - 2026-09-25

### Changed

- Prepare `nvl/auth` for independent Composer and Git publication; require `nvl/core` for shared Support and Data services.

## [2.1.1] - 2026-09-23

### Changed

- Replace bulk-user and role-clone Form Requests and inline membership
  validation with Data contracts. Preserve the existing HTTP responses and
  snake-case input while also accepting the generated camel-case aliases.

## [2.0.1] - 2026-09-22

### Changed

- Released unchanged under the suite's shared version.

## [2.0.0] - 2026-08-29

### Changed

- Changed role and permission management list items from Eloquent models to
  `RoleListItemData` and `PermissionListItemData` while preserving paginator
  metadata, authorization, counts, and ordering.
- Established the bounded Auth Actions and authorization contracts as the 2.0
  consumer boundary; direct consumer Auth-model queries now fail Suite audit.

## [1.0.6] - 2026-08-13

### Added

- Added a privacy-bounded, after-commit `InvitationAccepted` event for direct
  and registration-through-invitation acceptance paths.

## [1.0.5] - 2026-08-12

### Fixed

- Preserved application-defined `$fillable` attributes on User subclasses while
  merging the configured canonical principal columns, normalizing duplicates,
  and keeping unlisted attributes protected.

### Changed

- Documented host principal extension fields and sensitive self-service profile
  confirmation for email changes.

## [1.0.3] - 2026-08-12

### Fixed

- Restored the v1.0.1 Auth create-migration schema and added a forward-only,
  idempotent corrective migration for invitation `context_hash` and challenge
  `secondary_secret_hash` columns and indexes. Schema planning now reports and
  repairs incomplete enabled-feature tables, Doctor verifies both indexes, and
  the release workflow rehearses a real v1.0.1-to-v1.0.3 upgrade.

## [1.0.2] - 2026-08-12

### Changed

- Registered migration publication through Laravel's timestamp-aware API and
  made Doctor warn when automatic vendor loading overlaps a published host copy.
- Added versioned, dry-run-first legacy principal adoption with staging,
  password-reset-token preservation, extension columns, host foreign-key
  reconciliation, bounded validation, and explicit source cleanup.
- Added canonical-to-physical principal attribute mapping across the package
  model, Actions, validation, authentication metadata, and diagnostics.
- Made Auth migrations feature-aware and idempotent, with a schema planning and
  reconciliation command for features enabled after initial installation.
- Made Doctor reject physical principal columns that shadow Eloquent
  relationships on the configured User model.
- Made principal create/update Actions persist complete validated DTO payloads
  through the attribute mapper; update DTOs use `Optional` so omitted fields
  remain unchanged while explicit values are applied without duplicate wiring.
- Added replaceable authentication eligibility and account-confirmation
  contracts across credential, passwordless, social, password-reset, profile,
  and self-service deletion flows. Successful login metadata now records only
  after host policy and the login pipeline accept the subject.
- Added fail-closed Socialite verified-email provenance, atomic sparse email
  changes with verification restart, and complete self-delete session/token
  containment.
- Added explicitly authorized actorless invitation issuance, bounded expiry and
  return-path context, atomic invitation registration, exact blind-index
  filters, and replaceable registration mapping for host fields.
- Added compound magic-link challenges with one single-use link token and
  numeric fallback code plus direct challenge-ID callbacks. Delivery requests
  now reject feature/message-type mismatches.
- Decoupled RBAC principal lookup and assignment from package principal
  management through `RbacPrincipalAccess`; role and permission replacement
  Actions now consume validated DTOs and emit `RbacAssignmentChanged` from the
  common assignment boundary, including creation and invitation grants.
- Added validated rich role templates with display, description, system,
  hierarchy, priority, metadata, and caller-selected target-role support.
- Added `BootstrapRbacAction`, deterministic synchronization reports, and a
  denied-by-default `SystemMutationAccess` boundary for traceable actorless
  bootstrap, domain RBAC, and principal lifecycle transitions.
- Added replaceable `PrincipalSessionContainment` across disable, delete,
  restore, and bulk lifecycle paths. The Laravel adapter revokes package API
  tokens, rotates remember credentials, and removes database sessions.

## [1.0.1] - 2026-08-09

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

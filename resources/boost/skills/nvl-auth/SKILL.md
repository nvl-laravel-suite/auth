---
name: nvl-auth
description: Implement or review NVL Auth feature flags, Actions, routes, adapters, invitations, authenticators, clients, Sanctum, Spatie Permission, and delivery events.
---

# NVL Auth

Use this skill for work involving the `nvl/auth` Laravel package.

## Boundaries

- NVL Auth owns the default User, profiles, user management, and Auth policy.
- NVL Auth owns password-reset-token, Sanctum-token, and Spatie RBAC tables
  while using those frameworks' maintained behavior.
- Laravel owns live browser session/cookie mechanics.
- Consumer subclasses own application-specific User relationships and business
  authorization beyond Auth's management abilities.
- A host delivery package owns notifications, queues, retries, templates, and
  provider callbacks.
- NVL Auth owns feature admission, use-case Actions, optional routes, pipelines,
  users, profiles, RBAC, tokens, clients, invitations, challenges,
  authenticators, social links, and audits.

Never add shadow browser-session tables, a notification sender, a delivery outbox,
or an application-specific model/namespace to Auth.

## Implementation rules

1. Read `config/nvl-auth.php` and `FeatureManifest` before changing a feature.
2. Gate every public Action as its first operation.
3. Keep Actions as one-use-case transaction owners.
4. Put reusable provider/invariant logic behind a typed contract or Service.
5. Keep optional adapters lazy and fail closed through an unavailable adapter.
6. Add HTTP routes only through the owning feature/surface family and preserve
   `nvl-auth.feature` middleware.
7. Install only tables required by enabled features. When a feature is enabled
   later, plan and reconcile with `nvl:auth:schema`; keep migrations idempotent.
   A globally disabled provider must remain passive unless migration loading is
   explicitly requested.
8. Emit delivery through `AuthDeliveryRequested`; do not send it in Auth.
9. Update manifest route names, HTTP docs, OpenAPI, and contract tests together.
10. Keep the configured principal attribute map aligned across models, Actions,
    validation, authentication, adoption, and Doctor. Reject physical
    attribute/relationship collisions.
11. Persist validated principal DTO arrays as one mapped payload. Use
    `Optional` for sparse updates; never rebuild partial writes property by
    property or treat omitted values as `null`.
12. Adopt legacy principals only through a versioned dry-run-first manifest
    that reconciles counts, identifiers, hashes, tokens, and declared host FKs.
13. Run focused Pest, full Pest, PHPStan max, and Pint.
14. Apply `AuthenticationEligibility` after subject resolution in every login
    and password-reset flow; do not record success metadata before policy and
    pipeline acceptance.
15. Carry Socialite verified-email provenance and fail closed before any
    email-based subject resolution.
16. Keep profile mutations sparse. Email changes require account confirmation,
    atomically clear verification, and emit fresh verification delivery.
17. Keep invitation principal creation, RBAC, consumption, audit, and acceptance
    hooks in one transaction. Actorless issuance requires a trusted
    `InvitationIssuanceContext`; never hydrate it from public input.
18. Query encrypted invitation recipients only by exact blind index. Never
    decrypt and scan for substring search.

## Features

The closed catalog is: authentication, principal management, password, email verification, magic
links, security codes, invitations, TOTP, passkeys, recovery codes, social
identities, clients, sessions, API tokens, RBAC, and audit.

`revoke` and `cleanup` are containment operations and remain callable after
disablement. Normal read/enroll/issue/use/update operations require package
ingress, the feature, and its declared dependencies.

## References

- Read `references/verification.md` for challenge and delivery rules.
- Read `references/sms-security-codes.md` for numeric-code transport guidance.

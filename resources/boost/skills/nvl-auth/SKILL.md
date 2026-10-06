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

## Host workflow composition and tests

Inject focused `Nvl\Auth\Contracts\<Action basename without Action>Contract`
interfaces into host services, such as `ListApiTokensContract`,
`ListInvitationProjectionsContract`, and `LogoutContract`. Preserve the native
execute signatures, sensitive parameter attributes, generic DTO/model results,
and void returns. Substitute an interface through the host container, then
invoke a real host service; retain package integration coverage for admission,
authorization, persistence, sessions, and delivery effects. Use factories only
in tests and treat returned models as documented identity/result handles.

Focused defaults are transient `bindIf` bindings. Existing feature extension
defaults preserve host prebindings and retain their singleton/scoped lifetimes.
Late interface replacement reaches newly constructed host services; scoped
package defaults reset with the next native request/job scope. Keep concrete
Action constructors and internal Action chains unchanged. Adoption/pruning and
`Challenges\{IssueChallenge,ConsumeChallenge,ConsumeChallengeById}Action` remain
internal; use their public commands or complete feature workflows.

For neutral membership access, preserve genuine host adapters. Auth may upgrade
only Core's exact native unshared disabled fallback, using native factory
metadata without invocation. Do not replace aliases, instances, custom
closures/classes or singletons, infer defaults from namespace prefixes, or gate
replacement on historical transient resolution. See the package README's
host-injection examples and UPGRADING binding-precedence notes.

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
   Emit successful direct and registration-through-invitation consumption
   through the privacy-bounded, after-commit `InvitationAccepted` event. Never
   add its token, recipient, metadata, roles, or permissions to that event.
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
19. Keep RBAC principal lookup/assignment behind `RbacPrincipalAccess`; RBAC
    assignment does not require package principal management.
20. Return validated `RoleTemplate` values from providers and apply them through
    `ApplyRoleTemplateData`; do not pass raw template maps or role names into
    write Actions.
21. Actorless RBAC/lifecycle mutations require `SystemMutationContext` and host
    `SystemMutationAccess` approval. Never fabricate a human actor.
22. Contain disable/delete/restore transitions through
    `PrincipalSessionContainment`, including API tokens, remember credentials,
    database sessions, and host session stores.

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

## Configurable-tenancy release discipline

- Preserve disabled compatibility and package independence; tenant support never creates an undeclared Auth or Suite dependency.
- Use registered package-owned resources, adoption adapters, Actions, and lifecycle APIs. Never add a generic tenant delete-all path or raw cross-package cleanup.
- Treat mapping/configuration hashes, interruption checkpoints, conservation evidence, worker context, tenant-leading queries, and standalone consumption as release contracts.

## Shared consumer diagnostics

Run `php artisan nvl:doctor --strict --format=json` to combine checks from loaded NVL providers. Retain the package Doctor command for its detailed report; both paths reuse the package-owned inspection service.

### Brownfield storage identities

Resolve all package tables through the table helper and canonical `nvl-auth.tables.*`, connections through `nvl-auth.connection` with Core/Laravel inheritance. Defaults use `nvl_auth_*`; migration filenames include that package slug. Never silently adopt a matching table or generic migration filename. Run shared `nvl:doctor --strict --format=json` and the explicit `nvl:schema:upgrade --package=auth --claim-legacy --dry-run --format=json` before upgrading owned legacy storage. Validate the complete plan and choose one migration owner. Preserve host records, constraint names and stored morph values. Deprecated config inputs last one major; canonical options take precedence.

## Canonical configuration ownership

- Read/write `nvl-auth` configuration and publish only canonical `nvl-<package>-<resource>` tags. Keep logical package/tenant resource identifiers unchanged.
- Generic config roots and unprefixed package environment names are foreign by default. For an upgrading NVL host only, select `nvl-core.compatibility.legacy_config` package IDs and `legacy_env` explicitly; both default off. Canonical presence wins, including false/null/empty values. Legacy inputs are read without writing back and are removed in major 6.
- Use canonical `NVL_<PACKAGE>_*` variables only in config evaluation, then rebuild configuration caches and restart workers after cutover. Shared Laravel environment variables retain their names. Consult Core's versioned `support/resources/global-names.json` for all renames.
- Old global aliases and legacy route families require separate explicit `global_aliases`/`legacy_routes` package selections. Preserve collisions and use Doctor diagnostics; never grant generic permissions automatically or claim signed-link compatibility without the same authorization/signature checks.


## Consumer runtime and testing contracts

Start with the package README Quickstart and Testing your app sections. Use `nvl:install <package>` for loaded-package common config publication; it does not enable features, run schema or refresh caches. Preserve native host owner keys/morph maps and selected auth/tenancy defaults. Read full runtime defaults and publish advanced config only deliberately.

Inject the supported focused interfaces and preserve host bindings. Returned model handles do not permit package-table queries/writes outside documented capability/extension seams. Host tests may substitute contracts in Laravel's container, use shipped model factories (ordinary make may persist parents; withoutParents()->make is detached), and use Laravel effect fakes deliberately. Only Media/Stripe have dedicated provider/library fakes; do not invent a universal package fake. Settings InteractsWithSettings is definition-only. Host PHPStan may include vendor/nvl/core/support/consumer-audit.neon; no unpublished workbench command is a consumer requirement.

Read docs/events.md and the package README error table. Domain events use schemaVersion=1, model-free facts and actual source-connection commit callbacks; only six declared old Event suffix aliases remain for major 5. Migrate exact listeners/fakes and suffix wildcards, drain old queued payloads, rebuild event cache and restart workers. Delivery is not a durable outbox. The Core exception renderer is opt-in, JSON-only for respondable failures, with exactly message/code/context and host-selected locale. Do not expose diagnostics or reinterpret missing bindings as authorization denial.

Core package logging uses nvl/normal with CSV quiet by default, stable message keys and bounded context; incidents survive quiet. Do not mutate global logger context or log raw row/provider/content/credential payloads. Run only authorized project checks and report new acceptance as pending until actual output exists.

# Architecture

NVL Auth is one Composer package containing logical features. It is a complete
authentication platform, not an application-specific module: it owns the
default User/RBAC/token/authentication implementation while providing explicit
ports for consumer policy and cross-module relationships.

## Layer ownership

```text
optional JSON controller
  -> validates and normalizes transport input
Action
  -> gates its owning feature first
  -> authorizes management use
  -> owns one use case and transaction
Pipeline stages
  -> optional consumer policy around selected Actions
Service / adapter
  -> reusable invariant or provider integration
Model
  -> package persistence and relationships
After-commit event
  -> transport-neutral integration boundary
```

Controllers contain no business transactions. Services are not alternate public
entry points. Every public feature Action gates itself before querying or
mutating state, so direct PHP usage is protected exactly like the HTTP API.

## Runtime ownership

- `Nvl\Auth\Models\User` is the default Laravel authenticatable and owns
  identity, profile, active/deleted/locked state, password reset, email
  verification, roles, permissions, tokens, and Auth relationships.
- package Role and Permission models use Spatie Permission behavior over
  namespaced package tables.
- package PersonalAccessToken and its manager use Sanctum behavior over the
  namespaced package token table.
- Laravel guard/session APIs establish and end browser sessions; Auth stores
  only optional client-session correlation.
- the package password broker uses `nvl_auth_password_reset_tokens`.
- typed delivery events integrate mail/SMS/push without making Auth a transport
  or notification package.

## Provider layers

`AuthServiceProvider` always merges configuration, registers models/contracts,
configures Laravel authentication, password broker, Sanctum, and Spatie, loads
feature-aware migrations, publishes package assets, and registers operational
commands. Optional feature adapters remain lazy.

`RouteServiceProvider` loads only effective feature route families. Global,
surface, feature, route, and dependency switches must all pass. The same feature
middleware is attached to registered routes to protect stale route caches.

## Feature admission

`FeatureManifest` is the closed catalog for all 16 capabilities, operations,
dependencies, route families, route names, and management abilities.
`FeatureGate` evaluates the operation, package ingress, the feature switch, and
dependencies. Dependencies are never silently auto-enabled. Revoke/cleanup
containment can remain callable after a feature or ingress switch is disabled.

## Persistence and transactions

The two baseline migrations create only tables owned by enabled features.
`nvl:auth:schema` safely re-enters those idempotent migrations when a later
feature is enabled. Actions own use-case transactions on the package connection;
cross-table user/RBAC/invitation mutations are kept on that connection so they
can remain atomic. Feature flags alone never create, drop, or truncate data.

## Extension points

- configured User, Role, Permission, and PersonalAccessToken subclasses;
- configurable principal attribute mapping and a replaceable mapper contract;
- manifest-driven legacy-principal adoption with explicit host foreign keys;
- named `AuthPipelineStage` lists;
- identity, invitation, and social subject resolvers;
- password updater and management authorization ports;
- built-in replaceable WebAuthn ceremony;
- Socialite or another social acquisition adapter;
- Sanctum or another API-token manager and subject-aware ability provider;
- permission catalog and role-template providers;
- browser-session and audit-context ports;
- ordinary Laravel listeners for delivery and domain events.

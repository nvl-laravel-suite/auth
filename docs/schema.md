# Schema

NVL Auth owns a possible inventory of 17 UUID-first tables. Both package
migrations are idempotent and create only the tables required by features
enabled at migration time. Route switches never affect schema selection.

Run `php artisan nvl:auth:schema` before deploying newly enabled features. The
dry run reports required, existing, and missing tables. After review,
`php artisan nvl:auth:schema --apply` creates and verifies only the missing
feature-owned schema.

| Table | Purpose | Sensitive handling |
|---|---|---|
| `nvl_auth_users` | concrete authentication principals, profiles, status, login/lock state | passwords hashed by the model; last-login IP encrypted |
| `nvl_auth_permissions` | Spatie-compatible permission catalog | bounded metadata |
| `nvl_auth_roles` | Spatie-compatible roles, hierarchy, templates/system markers | bounded metadata |
| `nvl_auth_model_has_permissions` | direct principal permission assignments | UUID morph identity |
| `nvl_auth_model_has_roles` | principal role assignments | UUID morph identity |
| `nvl_auth_role_has_permissions` | role permission assignments | UUID foreign keys |
| `nvl_auth_personal_access_tokens` | package Sanctum tokens | one-way token hash; abilities and expiry bounded |
| `nvl_auth_password_reset_tokens` | Laravel password-broker reset tokens | broker-generated token hash |
| `nvl_auth_clients` | first-party client allowlists and return policy | bounded metadata |
| `nvl_auth_client_sessions` | correlation to a Laravel browser session | session ID hashed; IP, UA, metadata encrypted |
| `nvl_auth_invitations` | simple invitation lifecycle | token hashed; recipient and metadata encrypted |
| `nvl_auth_challenges` | magic links, codes, and passkey ceremony state | secrets hashed; adapter payload encrypted |
| `nvl_auth_totp_credentials` | TOTP authenticators | secret encrypted; replay timestep stored |
| `nvl_auth_passkeys` | WebAuthn credentials | credential ID, public key, and handle encrypted; blind index hashed |
| `nvl_auth_recovery_codes` | independently consumable recovery codes | purpose-separated one-way hashes |
| `nvl_auth_social_identities` | provider-to-principal links | provider identity and claims encrypted; blind index hashed |
| `nvl_auth_audits` | bounded authentication/action facts and payload metadata | IP, UA, and metadata encrypted |

Principal management owns Users; password owns reset tokens; RBAC owns its five
catalog/pivot tables; API tokens own Sanctum tokens; clients own clients and
client sessions; invitations own invitations; magic links/security codes share
challenges; TOTP, passkeys, recovery codes, and social identities each own their
credential table. Audit owns audits and also requires clients for optional
client correlation. Authentication, email verification, and browser-session
admission add no independent tables.

## Deliberately absent tables

The package does not create shadow browser sessions, mail notifications,
delivery attempts, queues, jobs, outboxes, workflow/saga projections, scheduler
checkpoints, or duplicated token/session projections. Laravel remains
authoritative for the running browser session; transport packages remain
authoritative for delivery execution.

## User extension and references

Package User rows are the default authentication principals. Credential tables
still use `subject_type` plus `subject_id`, allowing a configured subclass of
`Nvl\Auth\Models\User` and stable morph aliases without introducing a duplicate
principal projection. Consumer-specific foreign keys and cross-module
relationships belong on the subclass or its application-owned extension tables.
The complete physical principal attribute map is configurable; UUID identity is
still mandatory. Physical columns must not share names with relationships
declared by the configured User subclass.

## Connection and table names

All package models and migrations use `nvl-auth.connection` when configured.
Choose it before installation and treat it as immutable after data exists.
Changing the connection or a configured identity/RBAC/token table name requires
a coordinated schema and data migration, cache rebuild, worker restart, and
Doctor verification.

## Retention

`nvl:auth:prune` deletes old terminal invitations/challenges, revoked
authenticators/social links, used or revoked recovery codes, and ended client
session correlations. It never deletes Users, active credentials, clients,
roles, permissions, tokens, or immutable `nvl_auth_audits` facts.

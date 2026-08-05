# Feature manifest

`FeatureManifest` is the closed runtime catalog. There are fifteen definitions,
one for every `AuthFeature` enum case.

Management definitions also own their required host authorization abilities;
Doctor checks those abilities whenever the corresponding route family is
enabled and the default Laravel Gate adapter is used.

| Feature | Operations | Dependencies | HTTP surfaces |
|---|---|---|---|
| authentication | read, issue, use, update, revoke, cleanup | — | public, account |
| password | read, issue, use, update, revoke, cleanup | authentication | public, account |
| email_verification | read, issue, use, update, revoke, cleanup | authentication | public, account |
| magic_links | read, issue, use, update, revoke, cleanup | authentication | public |
| security_codes | read, issue, use, update, revoke, cleanup | authentication | public |
| invitations | read, issue, use, update, revoke, cleanup | — | public, management |
| totp | read, enroll, issue, use, update, revoke, cleanup | authentication | account |
| passkeys | read, enroll, issue, use, update, revoke, cleanup | authentication | public, account |
| recovery_codes | read, enroll, issue, use, update, revoke, cleanup | authentication | account |
| social_identities | read, enroll, issue, use, update, revoke, cleanup | authentication | public, account |
| clients | read, issue, use, update, revoke, cleanup | authentication | public, management |
| sessions | read, use, revoke | authentication | — |
| api_tokens | read, issue, use, update, revoke, cleanup | authentication | account |
| rbac | read, enroll, issue, use, update, revoke, cleanup | — | management |
| audit | read, issue, cleanup | — | management |

`revoke` and `cleanup` are containment operations. All other operations require
package ingress, the feature flag, and every declared dependency.

Route-only dependencies are also canonical: public login requires `password`
and `sessions`; public magic-link, passkey, and social authentication require
`sessions`; the account password family requires `sessions`. They affect route
registration and stale-cache middleware without over-constraining direct factor
Actions that do not establish a browser session.

## Route inventory

The manifest also owns every expected route name. A contract test compares the
all-enabled Laravel route collection to this inventory, and Doctor compares the
configured inventory to the routes actually loaded at runtime.

| Surface | Families |
|---|---|
| public | login, password reset, email verification, magic links, security codes, invitation acceptance, passkey authentication, social authorization, client start |
| account | logout, password update/confirmation, verification request, TOTP, passkeys, recovery codes, social links, API tokens |
| management | invitations, complete client management, RBAC synchronization, audit list/detail |

Routes additionally declare their exact feature operation in middleware. This
protects a stale route cache when a feature is disabled.

## Defaults

`authentication`, `password`, `sessions`, and `audit` are enabled. Every other
feature is disabled. All route layers and every feature route family are disabled.

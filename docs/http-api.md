# HTTP API

All HTTP routes are optional. Default prefix: `/api/v1/auth`. Route names start
with `nvl.auth.` and response envelopes use `data`, `code`, and `message`.

## Public surface

| Method and path | Route name | Feature/operation |
|---|---|---|
| `POST login` | `public.login` | authentication/use |
| `POST password/forgot` | `public.password.request` | password/issue |
| `POST password/reset` | `public.password.reset` | password/use |
| `GET email/verify/{id}/{hash}` | `public.email.verify` | email verification/use |
| `POST magic-links` | `public.magic_links.request` | magic links/issue |
| `POST magic-links/consume` | `public.magic_links.consume` | magic links/use |
| `POST security-codes` | `public.security_codes.request` | security codes/issue |
| `POST security-codes/verify` | `public.security_codes.verify` | security codes/use |
| `POST invitations/accept` | `public.invitations.accept` | invitations/use |
| `POST passkeys/authentication/options` | `public.passkeys.authentication.options` | passkeys/use |
| `POST passkeys/authentication` | `public.passkeys.authentication.finish` | passkeys/use |
| `GET social/{provider}/redirect` | `public.social.redirect` | social identities/issue |
| `GET social/{provider}/callback` | `public.social.callback` | social identities/use |
| `POST clients/start` | `public.clients.start` | clients/use |

## Account surface

| Method and path | Route name | Feature/operation |
|---|---|---|
| `GET profile` | `account.profile.show` | principal management/read |
| `PATCH profile` | `account.profile.update` | principal management/update |
| `POST logout` | `account.logout` | authentication/revoke |
| `PUT password` | `account.password.update` | password/update |
| `POST password/confirm` | `account.password.confirm` | password/use |
| `POST email/verification` | `account.email.request` | email verification/issue |
| `POST totp/enroll` | `account.totp.enroll` | TOTP/enroll |
| `POST totp/{credential}/confirm` | `account.totp.confirm` | TOTP/enroll |
| `POST totp/verify` | `account.totp.verify` | TOTP/use |
| `DELETE totp/{credential}` | `account.totp.revoke` | TOTP/revoke |
| `POST passkeys/registration/options` | `account.passkeys.registration.options` | passkeys/enroll |
| `POST passkeys/registration` | `account.passkeys.registration.finish` | passkeys/enroll |
| `DELETE passkeys/{passkey}` | `account.passkeys.revoke` | passkeys/revoke |
| `POST recovery-codes/regenerate` | `account.recovery_codes.regenerate` | recovery codes/issue |
| `POST recovery-codes/consume` | `account.recovery_codes.consume` | recovery codes/use |
| `DELETE recovery-codes` | `account.recovery_codes.revoke` | recovery codes/revoke |
| social link/callback/delete | `account.social.*` | social identities/enroll/revoke |
| API token list/create/update/rotate/delete | `account.api_tokens.*` | API token lifecycle |

## Management surface

| Family | Routes | Package abilities |
|---|---|---|
| users | list, suggestions, create, show, update, enable/disable, restore, delete, bulk operations | `nvl-auth.users.viewAny`, `.view`, `.create`, `.update`, `.delete`, `.restore` |
| user access | replace direct roles or permissions | `nvl-auth.users.manageAccess` |
| invitations | list, create, resend, revoke | `nvl-auth.invitations.*` |
| clients | list, show, create, update, activate/deactivate, delete | `nvl-auth.clients.*` |
| roles | list, show, create, update, delete, clone, hierarchy, templates, apply template, analytics | `nvl-auth.rbac.view`, `.manageRoles` |
| permissions | list, show, create, update, delete | `nvl-auth.rbac.view`, `.managePermissions` |
| RBAC synchronization | synchronize catalogs and templates | `nvl-auth.rbac.synchronize` |
| audits | list, authorized detail with metadata/context | `nvl-auth.audits.viewAny`, `nvl-auth.audits.view` |

## Errors

Package failures use the same envelope. Disabled or stale-cached features return:

```json
{
  "data": null,
  "code": "feature_unavailable",
  "message": "The requested authentication capability is unavailable."
}
```

Validation remains Laravel's standard `422` response. Management authorization
accepts the configured package super-admin role and otherwise delegates to
Laravel Gate; the contract is replaceable. Secrets are returned only by the endpoint that must deliver
them to the authenticated caller (for example recovery codes and a new Sanctum
plain-text token).

All package responses, including errors, set `Cache-Control: no-store, private`,
`Pragma: no-cache`, `Referrer-Policy: no-referrer`, and
`X-Content-Type-Options: nosniff`.

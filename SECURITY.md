# Security policy

Submit reports through [this package's private vulnerability reporting form](https://github.com/nvl-laravel-suite/auth/security/advisories/new).

Report vulnerabilities privately to the package maintainers. Do not open a
public issue containing secrets, exploit details, or affected production data.

This source targets the NVL Light `7.x` family, PHP `^8.4` and Laravel `^13.0`, as declared in Composer. Source changes and focused checks do not establish release certification. Production MySQL/PostgreSQL concurrency, Redis driver and clean distribution rehearsals require their own recorded release evidence; they were not rerun as part of the final focused implementation pass. No broader framework or database compatibility is implied.

Security-sensitive design rules:

- `APP_KEY` protects encrypted casts and purpose-separated blind indexes.
- Bearer tokens and codes are returned only at issuance and never stored in
  plaintext.
- Delivery secrets leave Auth only in an after-commit typed event; host listeners
  must prevent logging and own secure queue/transport handling.
- OAuth access and refresh tokens are not persisted by Auth.
- The built-in maintained WebAuthn adapter requires an RP ID, explicit HTTPS
  origins, stable user-handle key, user-verification policy, and counter handling;
  custom ceremony implementations must preserve the same verification boundary.
- Route flags are not an authorization policy. Management access still requires
  the host `AuthManagementAccess` contract.
- Changing `nvl-auth.connection` or `APP_KEY` after installation requires a
  coordinated data migration.

See [docs/security.md](docs/security.md) for operational guidance.

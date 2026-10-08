# Security policy

Submit reports through [this package's private vulnerability reporting form](https://github.com/nvl-laravel-suite/auth/security/advisories/new).

Report vulnerabilities privately to the package maintainers. Do not open a
public issue containing secrets, exploit details, or affected production data.

Security fixes are provided for the published `5.x` release line. Composer declares PHP `^8.4` and Laravel `^12.0|^13.0`. The local Dagger release gate verifies PHP 8.4/Laravel 13 with MySQL 8.4 and PostgreSQL 17 persistence contracts; PHP 8.5, Laravel 12 and MariaDB require separate compatibility evidence. Upstream security lifecycle limits still apply.

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

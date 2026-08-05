# Security policy

Report vulnerabilities privately to the package maintainers. Do not open a
public issue containing secrets, exploit details, or affected production data.

Supported versions are the current pre-1.0 development line and the latest
tagged release.

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

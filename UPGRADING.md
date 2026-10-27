# Upgrading to Auth Light

This is a breaking API conversion staged ahead of the coordinated major release. Current family metadata remains ^6.0 until that release. Replace every old Action/execute interface with the owning native service operation listed in [PHP API](docs/php-api.md). Pass native arrays instead of package Data and project models/results in the consumer. No old aliases or forwarding facades remain.

Move HTTP routing, controllers, validation extraction, CSRF, throttles, headers, cookies, redirects, exception presentation and OAuth Request/session acquisition into the application. Package installation no longer changes guards or password-broker configuration. Pass the guard and session explicitly for login/logout/session establishment. Credential verification alone is not login.

Use a host User subclass with optional Sanctum/Permission traits when enabling those adapters. Install selected adapter engines explicitly. Replace the old SocialIdentityProvider binding and features.social_identities.services.provider setting with a scoped SocialIdentityProviderFactory binding (or provider_factory setting). Construct a new SDK driver from the current request for every make call; see the [factory example](README.md). Keep audited SDK validation, TOTP/WebAuthn proofs, replay checks and canonical principal resolution intact.

Retired Tenancy configuration, model branches and automatic legacy-table conversion have no compatibility path. Preserve old data, drain or expire pending old proofs and queued payloads, and use reviewed native Ownership adoption before accepting scoped traffic. Native same-table ownership adoption does not copy or delete legacy tenant tables. Do not disable Ownership to escape persisted partition checks.

Keep source-transaction committed audit and delivery listeners, native queued envelopes and explicit actor/metadata contracts. Rebuild configuration/event caches and restart workers after deployment. Physical absence of optional dependencies requires a clean consumer dependency resolution; a development suite vendor directory does not prove it.

Map `users.manageCredentials` and `users.verifyEmail` explicitly in host management policies. Password edits or removal require the former; an explicit verified-email override requires the latter. An email change clears verification unless an authorized explicit override is supplied. Configure `features.password.services.policy` to replace the default new-password policy. Existing shorter credentials remain usable; bcrypt inputs over 72 bytes are always rejected. Password changes rotate native remember credentials without deleting unrelated application tokens or sessions.


## Mandatory authentication proofs

Apply `2026_10_27_000002_nvl_auth_ensure_authentication_challenges.php` under the existing migration owner. Native proof storage is mandatory even with magic links, security codes and TOTP disabled. Schema planning and Doctor require it. The forward migration intentionally repeats the frozen historical challenge definition so historical migrations remain unchanged; SchemaManager uses this same current creation/repair path. Existing business records survive, partial unsafe schemas require a data-preserving host migration, and host-owned migration mode never applies DDL automatically.

Replace removed `AuthenticationSessions::establish` / `establishForPurpose` with native proof-backed completion. Legacy/generic login links cannot be promoted; request fresh native authentication links. Email request methods now require trusted browser/guard context. Passkey begin requires context and finish returns a proof. Social browser login uses `startAuthentication` / `finishAuthentication`; existing account link management remains separate. See [method and continuation examples](docs/php-api.md#proof-backed-completion).

Enrolled MFA is mandatory across all login methods, including when TOTP is disabled. Restore an available enrolled/recovery method instead of relying on the feature flag to erase the requirement. Configure additional class-based assurance via `features.authentication.services.assurance`; consumers retain routes, requests, responses, delivery, UI and owner authorization.

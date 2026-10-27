# Upgrading to Auth Light

This is a breaking API conversion staged ahead of the coordinated major release. Current family metadata remains ^6.0 until that release. Replace every old Action/execute interface with the owning native service operation listed in [PHP API](docs/php-api.md). Pass native arrays instead of package Data and project models/results in the consumer. No old aliases or forwarding facades remain.

Move HTTP routing, controllers, validation extraction, CSRF, throttles, headers, cookies, redirects, exception presentation and OAuth Request/session acquisition into the application. Package installation no longer changes guards or password-broker configuration. Pass the guard and session explicitly for login/logout/session establishment. Credential verification alone is not login.

Use a host User subclass with optional Sanctum/Permission traits when enabling those adapters. Install selected adapter engines explicitly. Replace the old SocialIdentityProvider binding and features.social_identities.services.provider setting with a scoped SocialIdentityProviderFactory binding (or provider_factory setting). Construct a new SDK driver from the current request for every make call; see the [factory example](README.md). Keep audited SDK validation, TOTP/WebAuthn proofs, replay checks and canonical principal resolution intact.

Retired Tenancy configuration, model branches and automatic legacy-table conversion have no compatibility path. Preserve old data, drain or expire pending old proofs and queued payloads, and use reviewed native Ownership adoption before accepting scoped traffic. Native same-table ownership adoption does not copy or delete legacy tenant tables. Do not disable Ownership to escape persisted partition checks.

Keep source-transaction committed audit and delivery listeners, native queued envelopes and explicit actor/metadata contracts. Rebuild configuration/event caches and restart workers after deployment. Physical absence of optional dependencies requires a clean consumer dependency resolution; a development suite vendor directory does not prove it.

# Install and publish: nvl/auth

Targets PHP 8.4+ and Laravel 13. Install the selected NVL dependency closure on compatible 7.x versions.

```sh
composer require nvl/auth:^7.0
```

## Provider discovery

Composer package discovery registers these package-owned providers:

- `Nvl\Auth\Providers\AuthServiceProvider`

Do not publish or copy vendor providers into the application. If discovery is deliberately disabled, register these exact classes in the application’s `bootstrap/providers.php`. Host policy and extension bindings belong in an application provider; see [usage](usage.md) for which bindings are required.

## Skills

Laravel Boost discovers this folder at `resources/boost/skills/` in the installed Composer package. In the consumer application, run:

```sh
php artisan boost:install --skills --no-interaction
```

Select skills through the installed Boost configuration when setting it up interactively. `php artisan boost:update --no-interaction` refreshes selected resources. Boost is a consumer development tool, not a required runtime dependency of this package. Agent Skills folders can also be copied to the skill directory supported by another agent; copy the entire folder so references and any scripts remain available.

The package also exposes its native Laravel publish group:

```sh
php artisan vendor:publish --tag=nvl-auth-skills --no-interaction
```

That group copies the full skill tree to `.agents/skills`. Avoid force-overwriting application-authored changes; keep local conventions separate from vendor guidance.

## Publishable groups

- `nvl-auth-adoption`
- `nvl-auth-config`
- `nvl-auth-migrations`
- `nvl-auth-skills`
- `nvl-auth-translations`

## Configuration

```sh
php artisan vendor:publish --tag=nvl-auth-config --no-interaction
```

The consumer owns `config/nvl-auth.php`. Inspect the actual files registered by this package's config publish group; published sections differ between packages. Set deployment configuration before provider boot when it selects a model, registry or integration. Never store closures in cacheable configuration; bind behavior in an application provider. Rebuild configuration caches and restart long-lived workers after reviewed changes.

## Migrations

Choose exactly one migration owner before the first migration:

- **Vendor-loaded:** enable the package migration loader and run ordinary `php artisan migrate --no-interaction` after reviewing storage and bindings.
- **Published:** publish the tagged files, disable `nvl-auth.migrations.enabled` before migrating, then review and edit the application-owned copies before their first execution.

```sh
php artisan vendor:publish --tag=nvl-auth-migrations --no-interaction
```

Publish migrations once during initial setup. Laravel retimestamps published migrations; publishing again can create duplicate dated copies even without `--force`. Update config or skills with their separate tags, and avoid a blanket `--provider` publication after migration setup. Do not run both vendor and host migration copies. Keep applied history intact; evolve an installed schema with a new reviewed host migration. Preserve required keys, unique constraints, indexes, ownership declarations and transaction connection.

Configure `nvl-auth.connection` and supported table mappings before migrations, together with any host model declarations. Publication does not create tables, establish actor policy, admit an owner or prove native Ownership adoption.

## Artisan operations

These commands are registered by Composer-discovered package providers. Feature-gated commands require the corresponding enabled adapter/runtime. Read each installed command’s `--help` before supplying operation options:

- `php artisan nvl:auth:adopt-email-identities --help`
- `php artisan nvl:auth:adopt-principals --help`
- `php artisan nvl:auth:configuration --help`
- `php artisan nvl:auth:configure --help`
- `php artisan nvl:auth:doctor --help`
- `php artisan nvl:auth:schema --help`
- `php artisan nvl:auth:features --help`
- `php artisan nvl:auth:prune --help`

## Optional packages

Installing an optional library does not grant a policy decision or automatically enable an integration. The manifest suggests:

- `bacon/bacon-qr-code`: Renders server-side QR codes for TOTP provisioning when a headless URI is not sufficient.
- `laravel/sanctum`: Enables the explicitly selected API token adapter.
- `laravel/socialite`: Enables the optional OAuth identity adapter.
- `nvl/activity`: Can consume the package's after-commit audit and authentication events.
- `nvl/mail-notifications`: Can consume AuthDeliveryRequested events and deliver the typed payloads.
- `nvl/ownership`: Adds optional model-declared ownership, isolation, adoption and captured worker contexts.
- `paragonie/constant_time_encoding`: Required by the selected WebAuthn passkey adapter.
- `pragmarx/google2fa`: Enables the audited TOTP engine when selected.
- `spatie/laravel-permission`: Enables the explicitly selected permission and role adapter.
- `symfony/serializer`: Required by the selected WebAuthn passkey adapter.
- `symfony/uid`: Required by the selected WebAuthn passkey adapter.
- `web-auth/webauthn-lib`: Enables the audited WebAuthn passkey adapter.

## Verify the consumer

Use the package-specific checks in [usage](usage.md), verify required host bindings and run the affected consumer tests. Publishing files is not application or production certification. Preserve the documented explicit actor, revision, owner, locale and outer-commit requirements when adapting HTTP, CLI or jobs.

Official framework guidance: [Laravel package development](https://laravel.com/docs/13.x/packages) and [Boost third-party package skills](https://laravel.com/docs/13.x/boost#third-party-package-skills).

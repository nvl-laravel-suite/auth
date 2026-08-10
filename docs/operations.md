# Operations

## Readiness

Run after installation and every configuration/cache deployment:

```bash
php artisan nvl:auth:doctor
```

Doctor checks:

- tables required by currently enabled features and their complete required columns on the configured connection;
- known legacy overreaching tables;
- `APP_KEY`;
- enabled feature dependencies;
- configured password, session, audit-context, API-token, social, passkey, and subject adapters, including built-in passkey resolution;
- API-token ability policy and Socialite provider configuration;
- the closed pipeline catalog and every resolvable pipeline stage;
- host authorization abilities for enabled management route families;
- Sanctum and Spatie table readiness when their integrations are enabled;
- passkey RP/origin, timeout, resident-key, and user-verification policy;
- public invitation resolver readiness;
- configured versus loaded Auth route inventory.
- physical principal columns that shadow relationships on the configured User.

`--format=json` emits machine-readable checks and a top-level `ready` boolean.
`--strict` additionally fails for dormant service/adapter configuration owned by
a disabled feature; dormant adapters are never resolved during a normal check.

## Feature inventory

```bash
php artisan nvl:auth:features
php artisan nvl:auth:features --format=json
```

The command shows configured/effective state, dependencies, and route surfaces
for all sixteen manifest entries.

## Feature schema

Run the dry-run-first schema reconciler after changing feature configuration:

```bash
php artisan nvl:auth:schema
php artisan nvl:auth:schema --apply
php artisan nvl:auth:doctor
```

The plan contains only tables required by enabled features. In automatic vendor
mode, apply re-enters the idempotent package migrations, creates missing tables,
and fails if reconciliation is incomplete. In host-owned mode
(`migrations.enabled=false`), apply fails closed: update and run the maintained
published migrations, then rerun the plan and Doctor.

## Legacy principal adoption

Publish and edit the versioned sample manifest, then follow the staged workflow:

```bash
php artisan vendor:publish --tag=auth-adoption
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --stage
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --stage --apply
php artisan nvl:auth:schema --apply
php artisan nvl:auth:adopt-principals nvl-auth.principals.json
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --apply
php artisan nvl:auth:doctor --strict
```

Every mutation is opt-in. See [principal adoption](principal-adoption.md) for
preconditions, reconciliation, and the forward-only rollback boundary.

## Pruning

```bash
php artisan nvl:auth:prune --dry-run
php artisan nvl:auth:prune
```

The command uses `cleanup.retention_days` and affects only terminal operational
state. Dry-run reports counts without deleting rows. Audits, clients, active
credentials, Laravel sessions, Sanctum tokens, and Spatie data are untouched.

The package registers no schedule. If desired, the host owns it:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('nvl:auth:prune')
    ->daily()
    ->onOneServer()
    ->withoutOverlapping();
```

## Deployment sequence

```bash
php artisan optimize:clear
php artisan migrate --force
php artisan nvl:auth:schema --apply
php artisan config:cache
php artisan route:cache
php artisan queue:restart
php artisan nvl:auth:doctor
```

Rebuilding route cache is required for newly enabled families. Disabled stale
routes fail closed through middleware even before the cache is rebuilt.

## Disablement

1. Stop new enrollment/issuance with host policy if a drain period is needed.
2. Revoke active credentials through containment Actions.
3. Disable the feature.
4. rebuild configuration/routes and restart long-lived workers.
5. prune terminal records only under the approved retention policy.

Changing a flag never deletes data. Re-enabling can reactivate a still-valid,
unrevoked credential.

# Principal adoption

NVL Auth provides a versioned, manifest-driven bridge for moving an existing
first-party User table into the configured package principal model. Planning is
the default. Staging, import, source cleanup, and foreign-key replacement happen
only with `--apply`.

## Preconditions

- Back up the database and rehearse on a production-shaped copy.
- Keep source and target on the same configured database connection.
- Preserve UUID principal IDs and password/reset-token hashes.
- Inventory every host foreign key that references the source User table.
- Add application-owned extension target columns to the configured principal
  table before import.
- Publish and edit the sample:

```bash
php artisan vendor:publish --tag=auth-adoption
```

The manifest is installed as `nvl-auth.principals.json`. Version 1 requires an
explicit source mapping for every canonical principal attribute. Use `null`
only for optional values that should receive package defaults. Update
`expected_count` immediately before execution; a mismatch stops the plan.

`extension_columns` maps target principal columns to source columns.
`foreign_keys` lists application-owned references that must be detached during
staging and recreated against the configured target principal ID. The command
does not discover or guess undeclared references.

## Staged workflow

Use staging when a legacy table has a canonical target name such as `users` or
`password_reset_tokens`:

```bash
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --stage
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --stage --apply
php artisan nvl:auth:schema --apply
```

The stage plan validates table names and declared foreign keys. Apply renames
the source tables and detaches only the explicitly named references. Install the
feature-aware target schema after the source names are free.

Plan and apply the import separately:

```bash
php artisan nvl:auth:adopt-principals nvl-auth.principals.json
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --format=json
php artisan nvl:auth:adopt-principals nvl-auth.principals.json --apply
php artisan nvl:auth:doctor --strict
```

Import validates source/target columns, exact counts, UUID IDs, normalized unique
emails, bounded names, target ID/email/token conflicts, and every declared host
reference before writing. It copies password hashes unchanged, preserves reset
token hashes, normalizes JSON metadata, encrypts plaintext legacy login IPs, and
recreates declared foreign keys against the mapped target ID. Inserts and
reconciliation run in one transaction.

## Cleanup and rollback boundary

Keep `drop_sources` false for the initial production run. Validate authentication,
password reset, application relationships, host references, and row counts
before scheduling source removal. Setting it to true makes cleanup explicit and
forward-only.

The bridge does not promise automatic rollback after source tables are dropped.
Before that point, restore by reverting application configuration and retaining
the staged sources. After cleanup, recovery requires the deployment backup and a
host-owned restoration procedure.

The manifest and command are intentionally bounded by
`adoption.maximum_manifest_bytes` and `adoption.maximum_records`. Split larger
adoptions into a reviewed host migration or raise the limit only for a controlled
rehearsal and deployment.

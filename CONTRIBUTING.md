# Contributing

NVL Auth follows the repository backend architecture rules.

## Required boundaries

- Every public Action gates its owning feature before queries or side effects.
- Actions own use-case transactions; Services own reusable invariants.
- Controllers validate/normalize transport input and delegate to Actions.
- Models stay persistence-focused.
- The package must not send mail or duplicate Laravel browser-session state.
- The package owns its concrete User, namespaced Sanctum tokens, password reset
  tokens, and namespaced Spatie Permission schema.
- Application-specific User relationships belong in a configured subclass.
- Optional integrations must resolve lazily and fail closed when enabled without
  their adapter.
- Schema creation is never conditional on feature flags.

## Quality commands

From `packages/nvl/auth`:

```bash
../../../vendor/bin/pest --compact
../../../vendor/bin/phpstan analyse -c phpstan.neon.dist --memory-limit=2G
../../../vendor/bin/pint --format agent
composer validate --strict
```

Changes require focused Pest coverage. Integration behavior belongs in Feature
tests; pure feature-manifest behavior belongs in Unit tests. Do not add skipped
release claims, static-analysis baselines, or error suppressions.

## Schema changes

This package is pre-1.0. Keep one complete baseline migration until the first
stable release unless published releases require additive migrations. Never
condition a table or column on a feature flag.

## Public contracts

When changing routes, update the canonical `FeatureManifest`, HTTP docs, and
OpenAPI inventory in the same change. When changing the delivery payload, keep
secret redaction in `__debugInfo()` and document host listener responsibilities.

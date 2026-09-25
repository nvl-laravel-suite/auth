# Contributing

This public repository is a publication mirror of private source. Open an issue
here for a bug or proposal; include a reproduction and, if helpful, a patch.
Maintainers apply accepted changes in source and publish a mirror release.
Direct mirror pull requests do not update source. See the
[organization contribution guide](https://github.com/nvl-laravel-suite/.github/blob/main/CONTRIBUTING.md).

NVL Auth follows the package boundaries below.

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

From a standalone checkout of the public Auth repository:

```bash
composer install
composer quality
composer validate --strict
```

Changes require focused Pest coverage. Integration behavior belongs in Feature
tests; pure feature-manifest behavior belongs in Unit tests. Do not add skipped
release claims, static-analysis baselines, or error suppressions.

## Schema changes

Published baseline migrations are immutable. Add forward migrations for schema
changes, and never condition a table or column on a feature flag.

## Public contracts

When changing routes, update the canonical `FeatureManifest`, HTTP docs, and
OpenAPI inventory in the same change. When changing the delivery payload, keep
secret redaction in `__debugInfo()` and document host listener responsibilities.

# OpenAPI

[`openapi.json`](openapi.json) describes the optional HTTP surface. Every
operation includes:

- `operationId` equal to the full Laravel route name;
- `x-nvl-feature`;
- `x-nvl-feature-operation`;
- `x-nvl-route-surface`;
- `x-nvl-feature-dependencies`.

The focused route contract test compares the all-enabled Laravel route inventory
to the canonical `FeatureManifest`. When routes change, update the manifest,
route file, HTTP table, and OpenAPI operation in the same change.

The document intentionally describes transport shape and feature ownership. It
does not imply that routes are enabled by default.

Request bodies are defined for every operation that requires JSON input, with
write-only credential fields and the same bounds enforced by controllers. Shared
response components document the stable envelope and non-cacheable security
headers. The account and management surfaces remain protected by the host's
configured middleware; the listed session/bearer schemes describe the supported
Laravel/Sanctum patterns rather than replacing host authorization.

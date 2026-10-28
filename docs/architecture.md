# Architecture

Native service families contain complete operations. Narrow contracts remain only for genuine host/engine integrations. Models retain persistence invariants; value objects retain security or identity invariants. The consumer owns transport and presentation. See [PHP API](php-api.md).


## Composition and native authority

The complete native service owns proof consumption, canonical locking, security revisions, mandatory MFA/last-primary checks, persistence and source-committed facts. Consumer continuation hooks can veto or add application work in the same transaction, while preserving the exact native terminal result and identity. Asynchronous integration consumes captured facts. The consumer owns HTTP, UI, routing, responses, onboarding, mapping and policy adapters. Optional SDKs perform cryptographic/provider acquisition behind explicit factories; they do not replace native operation authority.

Browser authority is enrolled privately after successful native authentication and re-admitted before application authorization. Impersonation is an expiring request overlay over the original admitted browser; target identity never becomes a persistent login, remember token or worker capability.

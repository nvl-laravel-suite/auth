# Configuration

Select native features in `nvl-auth.features`. Configure host principal mappings and explicit management/system authorization. Configure guards and brokers in the host. Optional adapter engines and Spatie storage adoption require deliberate selection; no package route configuration exists. Inspect the selected graph with `nvl:auth:configuration` and `nvl:auth:doctor`.


`features.principal_management.services.authentication_policy` accepts a consumer `AccountAuthenticationPolicy`; native last-primary protection always runs before and after it. `features.social_identities.services.provider_factory` is the acquisition seam. Provider aliases are explicit, safe discovery exposes only label/enabled/reauthentication capability, and fixed issuer/realm changes require reviewed adoption of retained links. Custom Socialite driver factories construct fresh SDK drivers for each operation; optional email-proof policies must match the verified provider claims.

Managed sessions default disabled. Their settings define absolute lifetime (43,200 seconds by default) and the explicit `admission_integrated` deployment assertion. Impersonation defaults disabled and deny-by-default, requires managed sessions/authentication/audit, and accepts a consumer `ImpersonationAccess` policy plus a bounded duration (900 seconds by default). These settings do not install HTTP middleware. Configure host middleware and `nvl-managed-session` guard deliberately; see [upgrade steps](../UPGRADING.md).

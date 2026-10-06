# NVL auth events

This document describes the implemented source behavior. Executable acceptance proof is pending the final testing phase. The authoritative machine-readable schema is [event-catalog.json](../resources/event-catalog.json), catalog version `1`. Event `schemaVersion` is independent of catalog version.

## Publication and listener timing

The native host dispatcher receives the captured event after the supplied source connection outer commit, or immediately when that connection has no active transaction.

Callbacks attach to the matching native connection and current nesting record; native outer/savepoint rollback discards the corresponding callbacks.

Missing source transaction records fail before commit; Mail Notifications reports and drops unusable observations.

Host after-commit listeners and queue after_commit policies can add their own deferral after publication. Host transaction infrastructure and dispatcher bindings are preserved.

Local callbacks are not an outbox. Process exit between commit and callback can lose delivery; no crash durability or exactly-once delivery is promised.

One canonical object is dispatched per qualifying producer call. This is local publication, not cross-process deduplication or a guarantee that repeated observations are unique.

Use Nvl\Support\Events\DomainEventDispatcher::dispatch($event, $writerConnection). Native Event::dispatch() is immediate and has no package interception.

## Payload security and no-op behavior

Internal integration metadata, not a public HTTP feed. Authentication attempts/rejections carry the supplied identifier and reason. AuthDeliveryRequested is an explicit sensitive delivery capability: recipient, secret-bearing payload, expiry, invitation and context must stay within trusted delivery listeners. Audit/principal/RBAC facts carry identifiers and producer-shaped JSON metadata, not models. Arbitrary host-supplied mixed arrays are not recursively constrained by every event constructor.

Attempt, rejection, session and delivery observations can repeat for separate requests. Mutation events follow their writer branch; there is no generic cross-request deduplication. Native Laravel Verified and PasswordReset are framework events outside this catalog: Eloquent writers use their source commit boundary; non-Eloquent/custom updater paths retain synchronous behavior where no source connection seam exists.

InvitationAccepted custom serialization includes schemaVersion and restores old scalar acceptance payloads without it as version 1.

AuthDeliveryRequest preserves its own debug redaction and serialized delivery capability, including recipient and payload; redaction during inspection is not removal from the listener payload.

SubjectReference uses getMorphClass() for an Eloquent subject and class identity for a non-Eloquent authenticatable. AuthEventContext captures TenantContextMode and optional TenantId; it can derive a TenantJobEnvelope.

Actor/owner identifiers do not grant access. Listeners must preserve the captured ownership and apply their own authorization when reading storage. Readonly payload fields and native value objects are schema facts; public constructors with mixed arrays do not create a new recursive sanitization boundary. Package producer shapes are documented below; hosts must not attach models, mutable service objects or private arbitrary data.

## Canonical events

| Event | Schema version | Trigger |
| --- | --- | --- |
| [AuthAuditRecorded](#authauditrecorded) | 1 | Audit row persisted. |
| [AuthDeliveryRequested](#authdeliveryrequested) | 1 | Host delivery capability requested. |
| [AuthenticationAttempted](#authenticationattempted) | 1 | Guard authentication attempted. |
| [AuthenticationRejected](#authenticationrejected) | 1 | Guard authentication rejected. |
| [InvitationAccepted](#invitationaccepted) | 1 | Invitation accepted. |
| [PrincipalChanged](#principalchanged) | 1 | Principal mutation persisted. |
| [RbacAssignmentChanged](#rbacassignmentchanged) | 1 | Principal role/permission assignment persisted. |
| [RbacChanged](#rbacchanged) | 1 | Role/permission aggregate mutation persisted. |
| [UserAuthenticated](#userauthenticated) | 1 | Guard authentication completed. |
| [UserLoggedOut](#userloggedout) | 1 | Guard logout completed. |

### AuthAuditRecorded

`Nvl\Auth\Events\AuthAuditRecorded` · [source](../src/Events/AuthAuditRecorded.php) · event schema `1`.

Audit row persisted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$auditId` | `string` | public | `required` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$auditId` | `string` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Services/AuthAuditWriter.php](../src/Services/AuthAuditWriter.php) | `$audit->getConnection()` |

### AuthDeliveryRequested

`Nvl\Auth\Events\AuthDeliveryRequested` · [source](../src/Events/AuthDeliveryRequested.php) · event schema `1`.

Host delivery capability requested.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$request` | `Nvl\Auth\ValueObjects\AuthDeliveryRequest` | public | `required` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$request` | `Nvl\Auth\ValueObjects\AuthDeliveryRequest` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Authentication/RequestEmailVerificationAction.php](../src/Actions/Authentication/RequestEmailVerificationAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Challenges/IssueChallengeAction.php](../src/Actions/Challenges/IssueChallengeAction.php) | `$challenge->getConnection()` |
| [Actions/Invitations/CreateInvitationAction.php](../src/Actions/Invitations/CreateInvitationAction.php) | `$invitation->getConnection()` |
| [Actions/Invitations/ResendInvitationAction.php](../src/Actions/Invitations/ResendInvitationAction.php) | `$locked->getConnection()` |
| [Actions/Passwords/RequestPasswordResetAction.php](../src/Actions/Passwords/RequestPasswordResetAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Users/UpdateProfileAction.php](../src/Actions/Users/UpdateProfileAction.php) | `$user->getConnection()` |

### AuthenticationAttempted

`Nvl\Auth\Events\AuthenticationAttempted` · [source](../src/Events/AuthenticationAttempted.php) · event schema `1`.

Guard authentication attempted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$identifierName` | `string` | public | `required` | — |
| `$identifier` | `string` | public | `required` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$identifierName` | `string` | — |
| `$identifier` | `string` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Authentication/EstablishAuthenticatedSessionAction.php](../src/Actions/Authentication/EstablishAuthenticatedSessionAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Authentication/LoginAction.php](../src/Actions/Authentication/LoginAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |

### AuthenticationRejected

`Nvl\Auth\Events\AuthenticationRejected` · [source](../src/Events/AuthenticationRejected.php) · event schema `1`.

Guard authentication rejected.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$identifierName` | `string` | public | `required` | — |
| `$identifier` | `string` | public | `required` | — |
| `$reason` | `string` | public | `required` | — |
| `$subject` | `?Nvl\Auth\ValueObjects\SubjectReference` | public | `null` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$identifierName` | `string` | — |
| `$identifier` | `string` | — |
| `$reason` | `string` | — |
| `$subject` | `?Nvl\Auth\ValueObjects\SubjectReference` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Authentication/EstablishAuthenticatedSessionAction.php](../src/Actions/Authentication/EstablishAuthenticatedSessionAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Authentication/LoginAction.php](../src/Actions/Authentication/LoginAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Authentication/LoginAction.php](../src/Actions/Authentication/LoginAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Authentication/LoginAction.php](../src/Actions/Authentication/LoginAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |

### InvitationAccepted

`Nvl\Auth\Events\InvitationAccepted` · [source](../src/Events/InvitationAccepted.php) · event schema `1`.

Invitation accepted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$invitationId` | `string` | public | `required` | — |
| `$type` | `string` | public | `required` | — |
| `$purpose` | `string` | public | `required` | — |
| `$subject` | `Nvl\Auth\ValueObjects\SubjectReference` | public | `required` | — |
| `$acceptedAt` | `?Carbon\CarbonImmutable` | public | `null` | — |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | public | `null` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$invitationId` | `string` | — |
| `$type` | `string` | — |
| `$purpose` | `string` | — |
| `$subject` | `Nvl\Auth\ValueObjects\SubjectReference` | — |
| `$acceptedAt` | `?Carbon\CarbonImmutable` | — |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Invitations/AcceptInvitationAction.php](../src/Actions/Invitations/AcceptInvitationAction.php) | `$invitation->getConnection()` |
| [Actions/Invitations/AcceptInvitationAction.php](../src/Actions/Invitations/AcceptInvitationAction.php) | `$invitation->getConnection()` |
| [Actions/Invitations/RegisterInvitationAction.php](../src/Actions/Invitations/RegisterInvitationAction.php) | `$invitation->getConnection()` |

### PrincipalChanged

`Nvl\Auth\Events\PrincipalChanged` · [source](../src/Events/PrincipalChanged.php) · event schema `1`.

Principal mutation persisted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$userId` | `string` | public | `required` | — |
| `$operation` | `string` | public | `required` | — |
| `$payload` | `array` | public | `[]` | `array<string, mixed>` |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | public | `null` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$userId` | `string` | — |
| `$operation` | `string` | — |
| `$payload` | `array` | `array<string, mixed>` |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Invitations/RegisterInvitationAction.php](../src/Actions/Invitations/RegisterInvitationAction.php) | `$invitation->getConnection()` |
| [Actions/Users/BulkUpdateUsersAction.php](../src/Actions/Users/BulkUpdateUsersAction.php) | `$user->getConnection()` |
| [Actions/Users/CreateUserAction.php](../src/Actions/Users/CreateUserAction.php) | `$user->getConnection()` |
| [Actions/Users/DeleteOwnAccountAction.php](../src/Actions/Users/DeleteOwnAccountAction.php) | `$user->getConnection()` |
| [Actions/Users/DeleteUserAction.php](../src/Actions/Users/DeleteUserAction.php) | `$user->getConnection()` |
| [Actions/Users/RestoreUserAction.php](../src/Actions/Users/RestoreUserAction.php) | `$user->getConnection()` |
| [Actions/Users/SetUserActiveAction.php](../src/Actions/Users/SetUserActiveAction.php) | `$user->getConnection()` |
| [Actions/Users/UpdateProfileAction.php](../src/Actions/Users/UpdateProfileAction.php) | `$user->getConnection()` |
| [Actions/Users/UpdateUserAction.php](../src/Actions/Users/UpdateUserAction.php) | `$user->getConnection()` |

### RbacAssignmentChanged

`Nvl\Auth\Events\RbacAssignmentChanged` · [source](../src/Events/RbacAssignmentChanged.php) · event schema `1`.

Principal role/permission assignment persisted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$principalId` | `string` | public | `required` | — |
| `$operation` | `string` | public | `required` | — |
| `$roles` | `array` | public | `[]` | `list<string>` |
| `$permissions` | `array` | public | `[]` | `list<string>` |
| `$metadata` | `array` | public | `[]` | `array<string, mixed>` |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | public | `null` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$principalId` | `string` | — |
| `$operation` | `string` | — |
| `$roles` | `array` | `list<string>` |
| `$permissions` | `array` | `list<string>` |
| `$metadata` | `array` | `array<string, mixed>` |
| `$context` | `?Nvl\Auth\ValueObjects\AuthEventContext` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Services/RbacManager.php](../src/Services/RbacManager.php) | `\Illuminate\Support\Facades\DB::connection($this->principals->connectionName($subject))` |
| [Services/RbacManager.php](../src/Services/RbacManager.php) | `\Illuminate\Support\Facades\DB::connection($this->principals->connectionName($subject))` |
| [Services/RbacManager.php](../src/Services/RbacManager.php) | `\Illuminate\Support\Facades\DB::connection($this->principals->connectionName($subject))` |

### RbacChanged

`Nvl\Auth\Events\RbacChanged` · [source](../src/Events/RbacChanged.php) · event schema `1`.

Role/permission aggregate mutation persisted.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$entityType` | `string` | public | `required` | — |
| `$entityId` | `string` | public | `required` | — |
| `$operation` | `string` | public | `required` | — |
| `$payload` | `array` | public | `[]` | `array<string, mixed>` |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$entityType` | `string` | — |
| `$entityId` | `string` | — |
| `$operation` | `string` | — |
| `$payload` | `array` | `array<string, mixed>` |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Rbac/AddRolePermissionsAction.php](../src/Actions/Rbac/AddRolePermissionsAction.php) | `$result['role']->getConnection()` |
| [Actions/Rbac/ApplyRoleTemplateAction.php](../src/Actions/Rbac/ApplyRoleTemplateAction.php) | `$role->getConnection()` |
| [Actions/Rbac/CloneRoleAction.php](../src/Actions/Rbac/CloneRoleAction.php) | `$clone->getConnection()` |
| [Actions/Rbac/CreatePermissionAction.php](../src/Actions/Rbac/CreatePermissionAction.php) | `$permission->getConnection()` |
| [Actions/Rbac/CreatePermissionWithRolesAction.php](../src/Actions/Rbac/CreatePermissionWithRolesAction.php) | `$result['permission']->getConnection()` |
| [Actions/Rbac/CreateRoleAction.php](../src/Actions/Rbac/CreateRoleAction.php) | `$role->getConnection()` |
| [Actions/Rbac/DeletePermissionAction.php](../src/Actions/Rbac/DeletePermissionAction.php) | `$permission->getConnection()` |
| [Actions/Rbac/DeleteRoleAction.php](../src/Actions/Rbac/DeleteRoleAction.php) | `$role->getConnection()` |
| [Actions/Rbac/SyncRolePermissionsAction.php](../src/Actions/Rbac/SyncRolePermissionsAction.php) | `$result['role']->getConnection()` |
| [Actions/Rbac/UpdatePermissionAction.php](../src/Actions/Rbac/UpdatePermissionAction.php) | `$permission->getConnection()` |
| [Actions/Rbac/UpdateRoleAction.php](../src/Actions/Rbac/UpdateRoleAction.php) | `$role->getConnection()` |

### UserAuthenticated

`Nvl\Auth\Events\UserAuthenticated` · [source](../src/Events/UserAuthenticated.php) · event schema `1`.

Guard authentication completed.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$subject` | `Nvl\Auth\ValueObjects\SubjectReference` | public | `required` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$subject` | `Nvl\Auth\ValueObjects\SubjectReference` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Authentication/EstablishAuthenticatedSessionAction.php](../src/Actions/Authentication/EstablishAuthenticatedSessionAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |
| [Actions/Authentication/LoginAction.php](../src/Actions/Authentication/LoginAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |

### UserLoggedOut

`Nvl\Auth\Events\UserLoggedOut` · [source](../src/Events/UserLoggedOut.php) · event schema `1`.

Guard logout completed.

Constructor parameters, in native order:

| Parameter | Native PHP type | Visibility | Default | Collection shape |
| --- | --- | --- | --- | --- |
| `$subject` | `?Nvl\Auth\ValueObjects\SubjectReference` | public | `required` | — |
| `$schemaVersion` | `int` | public | `1` | — |

Public payload fields:

| Field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$subject` | `?Nvl\Auth\ValueObjects\SubjectReference` | — |
| `$schemaVersion` | `int` | — |

Producers and exact scheduling connection expressions (variables are resolved in the linked source):

| Producer | Source connection |
| --- | --- |
| [Actions/Authentication/LogoutAction.php](../src/Actions/Authentication/LogoutAction.php) | `(new \Nvl\Auth\Models\AuthAudit)->getConnection()` |

## Referenced payload types

Native event field types are listed above; nested declared fields and backed enum values follow. Private captured envelopes are included because serialized/queued objects retain them. Dates use `Carbon\CarbonImmutable`. Spatie Data serialization can also carry its protected transformation metadata; recursive graph acceptance checks remain pending.

### AuthSubjectReferenceData

`Nvl\Auth\Data\Display\AuthSubjectReferenceData` · [source](../src/Data/Display/AuthSubjectReferenceData.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$type` | `string` | — |
| `$id` | `string` | — |

### InvitationDeliveryData

`Nvl\Auth\Data\Display\InvitationDeliveryData` · [source](../src/Data/Display/InvitationDeliveryData.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$id` | `string` | — |
| `$type` | `string` | — |
| `$purpose` | `string` | — |
| `$recipient` | `string` | — |
| `$inviter` | `?Nvl\Auth\Data\Display\AuthSubjectReferenceData` | — |
| `$roles` | `array` | `list<string>` |
| `$permissions` | `array` | `list<string>` |
| `$metadata` | `array` | `array<string, bool\|float\|int\|string\|null>` |
| `$expiresAt` | `Carbon\CarbonImmutable` | — |
| `$resendCount` | `int` | — |

### AuthFeature

`Nvl\Auth\Enums\AuthFeature` · [source](../src/Enums/AuthFeature.php).

Backed string values: `Authentication = authentication`, `PrincipalManagement = principal_management`, `Memberships = memberships`, `Password = password`, `EmailVerification = email_verification`, `MagicLinks = magic_links`, `SecurityCodes = security_codes`, `Invitations = invitations`, `Totp = totp`, `Passkeys = passkeys`, `RecoveryCodes = recovery_codes`, `SocialIdentities = social_identities`, `Clients = clients`, `Sessions = sessions`, `ApiTokens = api_tokens`, `Rbac = rbac`, `Audit = audit`.

### AuthMessageType

`Nvl\Auth\Enums\AuthMessageType` · [source](../src/Enums/AuthMessageType.php).

Backed string values: `Invitation = invitation`, `MagicLink = magic_link`, `SecurityCode = security_code`, `PasswordReset = password_reset`, `EmailVerification = email_verification`.

### AuthDeliveryRequest

`Nvl\Auth\ValueObjects\AuthDeliveryRequest` · [source](../src/ValueObjects/AuthDeliveryRequest.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$messageId` | `string` | — |
| `$feature` | `Nvl\Auth\Enums\AuthFeature` | — |
| `$type` | `Nvl\Auth\Enums\AuthMessageType` | — |
| `$recipient` | `string` | — |
| `$payload` | `array` | `array<string, mixed>` |
| `$expiresAt` | `Carbon\CarbonImmutable` | — |
| `$locale` | `?string` | — |
| `$metadata` | `array` | `array<string, mixed>` |
| `$subject` | `?Nvl\Auth\ValueObjects\SubjectReference` | — |
| `$invitation` | `?Nvl\Auth\Data\Display\InvitationDeliveryData` | — |
| `$tenant` | `?Nvl\Support\Tenancy\ValueObjects\TenantId` | — |
| `$eventContext` | `?Nvl\Auth\ValueObjects\AuthEventContext` | — |

### AuthEventContext

`Nvl\Auth\ValueObjects\AuthEventContext` · [source](../src/ValueObjects/AuthEventContext.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$mode` | `Nvl\Support\Tenancy\Enums\TenantContextMode` | — |
| `$tenantId` | `?Nvl\Support\Tenancy\ValueObjects\TenantId` | — |

### SubjectReference

`Nvl\Auth\ValueObjects\SubjectReference` · [source](../src/ValueObjects/SubjectReference.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$type` | `string` | — |
| `$identifier` | `string` | — |

### TenantContextMode

`Nvl\Support\Tenancy\Enums\TenantContextMode` · [source](../../core/support/src/Tenancy/Enums/TenantContextMode.php).

Backed string values: `Disabled = disabled`, `Unresolved = unresolved`, `Tenant = tenant`, `Platform = platform`.

### TenantId

`Nvl\Support\Tenancy\ValueObjects\TenantId` · [source](../../core/support/src/Tenancy/ValueObjects/TenantId.php).

| Declared public field | Native PHP type | Collection shape |
| --- | --- | --- |
| `$value` | `string` | — |

## Deferred acceptance checks

Final testing must compare catalog types/defaults/aliases with actual classes, recursively inspect producer payloads, and prove source outer commit, nested rollback, unrelated connection independence and retry behavior without an uncommitted test-harness transaction. Where applicable it must cover legacy exact/cached/queued listeners, canonical fakes and wildcard delivery, tenant capture, package no-op guards and observational failure containment. This document does not report those checks as passing.

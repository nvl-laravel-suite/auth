# Auth native events

Event facts publish through the source transaction boundary. AuthDeliveryRequested is a sensitive delivery capability; redact recipient and secret payloads. Its native OwnershipJobEnvelope captures source facts and worker admission revalidates availability. AuthEventContext contains native ownership classification, never actor authority. No legacy event aliases are shipped.

## AuthAuditRecorded

Audit row persisted.

| Field | Native type |
|---|---|
| `auditId` | `string` |
| `schemaVersion` | `int` |

## AuthDeliveryRequested

Host delivery capability requested.

| Field | Native type |
|---|---|
| `request` | `Nvl\Auth\ValueObjects\AuthDeliveryRequest` |
| `schemaVersion` | `int` |

## AuthenticationAttempted

Guard authentication attempted.

| Field | Native type |
|---|---|
| `identifierName` | `string` |
| `identifier` | `string` |
| `schemaVersion` | `int` |

## AuthenticationRejected

Guard authentication rejected.

| Field | Native type |
|---|---|
| `identifierName` | `string` |
| `identifier` | `string` |
| `reason` | `string` |
| `subject` | `?Nvl\Auth\ValueObjects\SubjectReference` |
| `schemaVersion` | `int` |

## InvitationAccepted

Invitation accepted.

| Field | Native type |
|---|---|
| `invitationId` | `string` |
| `type` | `string` |
| `purpose` | `string` |
| `subject` | `Nvl\Auth\ValueObjects\SubjectReference` |
| `acceptedAt` | `?Carbon\CarbonImmutable` |
| `context` | `?Nvl\Auth\ValueObjects\AuthEventContext` |
| `schemaVersion` | `int` |

## PrincipalChanged

Principal mutation persisted.

| Field | Native type |
|---|---|
| `userId` | `string` |
| `operation` | `string` |
| `payload` | `array` |
| `context` | `?Nvl\Auth\ValueObjects\AuthEventContext` |
| `schemaVersion` | `int` |

## RbacAssignmentChanged

Principal role/permission assignment persisted.

| Field | Native type |
|---|---|
| `principalId` | `string` |
| `operation` | `string` |
| `roles` | `array` |
| `permissions` | `array` |
| `metadata` | `array` |
| `context` | `?Nvl\Auth\ValueObjects\AuthEventContext` |
| `schemaVersion` | `int` |

## RbacChanged

Role/permission aggregate mutation persisted.

| Field | Native type |
|---|---|
| `entityType` | `string` |
| `entityId` | `string` |
| `operation` | `string` |
| `payload` | `array` |
| `schemaVersion` | `int` |

## UserAuthenticated

Guard authentication completed.

| Field | Native type |
|---|---|
| `subject` | `Nvl\Auth\ValueObjects\SubjectReference` |
| `schemaVersion` | `int` |

## UserLoggedOut

Guard logout completed.

| Field | Native type |
|---|---|
| `subject` | `?Nvl\Auth\ValueObjects\SubjectReference` |
| `schemaVersion` | `int` |

Source audit/delivery callbacks wait for the outer source commit; rollback emits no committed mutation fact. The durable committed-audit delivery protocol retains retry behavior. Framework Verified and PasswordReset remain Laravel events. Attempts/rejections and repeated delivery observations are not a cross-request exactly-once protocol.

See the machine-readable [event catalog](../resources/event-catalog.json) for the native payload schema.

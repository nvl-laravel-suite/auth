# Delivery events

NVL Auth does not send mail, SMS, push, or notifications. It owns only the auth
state transition and publishes `AuthDeliveryRequested` after commit.

## Payload

The event exposes `AuthDeliveryRequest`:

| Field | Meaning |
|---|---|
| `messageId` | host deduplication/idempotency key |
| `feature` | owning `AuthFeature` |
| `type` | password reset, email verification, magic link, security code, or invitation |
| `recipient` | transport-neutral destination string |
| `payload` | secret-bearing template/URL input, limited to 32 KiB encoded |
| `expiresAt` | auth credential expiry |
| `locale` | optional requested locale |
| `metadata` | non-authoritative context, limited to 16 KiB encoded |
| `subject` | optional challenged `SubjectReference` for subject-bound delivery |
| `invitation` | optional bounded `InvitationDeliveryData` for invitation rendering |

Debug inspection redacts the recipient and payload values. Application logging,
queue serialization, tracing, and exception reporting remain host concerns.
Invitation context contains no token hashes, active keys, context hashes, or
current delivery message IDs. Its `metadata` contains only bounded scalar values
whose keys are explicitly allowlisted in
`features.invitations.settings.delivery_metadata_keys`.

## Listener example

```php
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Actions\Invitations\RecordInvitationDeliveryOutcomeAction;
use Nvl\Auth\Services\FeatureGate;

final readonly class DeliverAuthRequest
{
    public function __construct(
        private FeatureGate $features,
        private RecordInvitationDeliveryOutcomeAction $outcomes,
    ) {}

    public function handle(AuthDeliveryRequested $event): void
    {
        $request = $event->request;

        if (! $this->features->allows($request->feature, FeatureOperation::Issue)) {
            return;
        }

        // Render with the typed subject/invitation context, then send the
        // secret-bearing payload through the selected transport.

        if ($request->invitation !== null) {
            $this->outcomes->execute(
                $request->invitation->id,
                $request->messageId,
                InvitationDeliveryStatus::Delivered,
                now()->toImmutable(),
            );
        }
    }
}
```

On a failed invitation attempt, report `InvitationDeliveryStatus::Failed` with
a stable 1–120 character code such as `provider_rejected`. Do not pass exception
messages. The Action locks the current invitation, ignores and audits callbacks
for superseded resend message IDs, and applies duplicate callbacks
idempotently. `Pending` is package-managed when an invitation is created or
resent and is not accepted as a transport result.

The host listener owns:

- selecting mail/SMS/push and templates;
- durable queueing and retries;
- idempotency by `messageId`;
- tracking provider IDs and callbacks;
- feature rechecks immediately before transport;
- cancelling expired requests;
- redacting secrets from logs;
- detailed transport audit policy.

Auth persists only the current coarse invitation outcome and its safe failure
code. It does not store provider payloads, exception text, attempt histories,
queues, or transport telemetry. This keeps the package installable in
applications that use any notification system—or none.

## Invitation reads

Use `ListInvitationProjectionsAction` for authorized paginated management reads
and `FindActiveInvitationAction` for an exact active lookup. Both return
`InvitationReadData`, never an `Invitation` model. The active lookup accepts a
management actor or an explicit trusted
`InvitationIssuanceContext(actorlessAuthorized: true)` from server-side
orchestration. Public input must never construct that trust context.

`ResendInvitationAction` and `RevokeInvitationAction` accept an invitation ID,
resolve and lock the current row, then authorize against that row. This lets a
consumer keep package models out of controllers, listeners, and application
services.

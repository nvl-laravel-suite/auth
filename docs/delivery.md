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

Debug inspection redacts the recipient and payload values. Application logging,
queue serialization, tracing, and exception reporting remain host concerns.

## Listener example

```php
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Services\FeatureGate;

final readonly class DeliverAuthRequest
{
    public function __construct(private FeatureGate $features) {}

    public function handle(AuthDeliveryRequested $event): void
    {
        $request = $event->request;

        if (! $this->features->allows($request->feature, FeatureOperation::Issue)) {
            return;
        }

        // Map $request to nvl/mail-notifications or another delivery package.
    }
}
```

The host listener owns:

- selecting mail/SMS/push and templates;
- durable queueing and retries;
- idempotency by `messageId`;
- tracking provider IDs and callbacks;
- feature rechecks immediately before transport;
- cancelling expired requests;
- redacting secrets from logs;
- delivery audit policy.

Auth owns none of that persistence. This keeps the package installable in
applications that use any notification system—or none.

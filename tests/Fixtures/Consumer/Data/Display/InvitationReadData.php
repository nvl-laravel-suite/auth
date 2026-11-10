<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Value-only invitation state for management lists and trusted lookup results.
 *
 * @api
 */
final class InvitationReadData implements Arrayable, JsonSerializable
{
    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, bool|float|int|string|null>  $metadata
     */
    public function __construct(
        public readonly string $id,
        public readonly string $recipient,
        public readonly string $type,
        public readonly string $purpose,
        public readonly ?AuthSubjectReferenceData $inviter,
        public readonly ?AuthSubjectReferenceData $acceptedBy,
        public readonly array $roles,
        public readonly array $permissions,
        public readonly array $metadata,
        public readonly string $lifecycle,
        public readonly int $resendCount,
        public readonly ?CarbonImmutable $lastSentAt,
        public readonly CarbonImmutable $expiresAt,
        public readonly ?CarbonImmutable $acceptedAt,
        public readonly ?CarbonImmutable $revokedAt,
        public readonly ?InvitationDeliveryStatus $deliveryStatus,
        public readonly ?CarbonImmutable $deliveryAttemptedAt,
        public readonly ?CarbonImmutable $deliveredAt,
        public readonly ?CarbonImmutable $deliveryFailedAt,
        public readonly ?string $deliveryFailureCode,
    ) {}

    /**
     * Build a read projection from one already loaded invitation.
     *
     * @internal
     */
    public static function fromModel(
        Invitation $invitation,
        array $delivery,
    ): self {
        $acceptedBy = $invitation->accepted_by_type !== null && $invitation->accepted_by_id !== null
            ? AuthSubjectReferenceData::fromReference(new SubjectReference(
                $invitation->accepted_by_type,
                $invitation->accepted_by_id,
            ))
            : null;

        return new self(
            id: $delivery['id'],
            recipient: $delivery['recipient'],
            type: $delivery['type'],
            purpose: $delivery['purpose'],
            inviter: $delivery['inviter'] === null ? null : new AuthSubjectReferenceData($delivery['inviter']['type'], $delivery['inviter']['identifier']),
            acceptedBy: $acceptedBy,
            roles: $delivery['roles'],
            permissions: $delivery['permissions'],
            metadata: $delivery['metadata'],
            lifecycle: self::lifecycle($invitation),
            resendCount: $delivery['resendCount'],
            lastSentAt: $invitation->last_sent_at,
            expiresAt: $delivery['expiresAt'],
            acceptedAt: $invitation->accepted_at,
            revokedAt: $invitation->revoked_at,
            deliveryStatus: $invitation->delivery_status,
            deliveryAttemptedAt: $invitation->delivery_attempted_at,
            deliveredAt: $invitation->delivered_at,
            deliveryFailedAt: $invitation->delivery_failed_at,
            deliveryFailureCode: $invitation->delivery_failure_code,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'recipient' => $this->recipient,
            'type' => $this->type,
            'purpose' => $this->purpose,
            'inviter' => $this->inviter?->toArray(),
            'acceptedBy' => $this->acceptedBy?->toArray(),
            'roles' => $this->roles,
            'permissions' => $this->permissions,
            'metadata' => $this->metadata,
            'lifecycle' => $this->lifecycle,
            'resendCount' => $this->resendCount,
            'lastSentAt' => $this->lastSentAt?->format(DATE_ATOM),
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
            'acceptedAt' => $this->acceptedAt?->format(DATE_ATOM),
            'revokedAt' => $this->revokedAt?->format(DATE_ATOM),
            'deliveryStatus' => $this->deliveryStatus?->value,
            'deliveryAttemptedAt' => $this->deliveryAttemptedAt?->format(DATE_ATOM),
            'deliveredAt' => $this->deliveredAt?->format(DATE_ATOM),
            'deliveryFailedAt' => $this->deliveryFailedAt?->format(DATE_ATOM),
            'deliveryFailureCode' => $this->deliveryFailureCode,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Resolve the stable invitation lifecycle label.
     */
    private static function lifecycle(Invitation $invitation): string
    {
        if ($invitation->accepted_at !== null) {
            return 'accepted';
        }

        if ($invitation->revoked_at !== null) {
            return 'revoked';
        }

        return $invitation->expires_at->isPast() ? 'expired' : 'active';
    }
}

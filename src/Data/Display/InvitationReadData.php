<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Carbon\CarbonImmutable;
use Nvl\Auth\Enums\InvitationDeliveryStatus;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Value-only invitation state for management lists and trusted lookup results.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class InvitationReadData extends Data
{
    use DataTransform;

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
     */
    public static function fromModel(
        Invitation $invitation,
        InvitationDeliveryData $delivery,
    ): self {
        $acceptedBy = $invitation->accepted_by_type !== null && $invitation->accepted_by_id !== null
            ? AuthSubjectReferenceData::fromReference(new SubjectReference(
                $invitation->accepted_by_type,
                $invitation->accepted_by_id,
            ))
            : null;

        return new self(
            id: $delivery->id,
            recipient: $delivery->recipient,
            type: $delivery->type,
            purpose: $delivery->purpose,
            inviter: $delivery->inviter,
            acceptedBy: $acceptedBy,
            roles: $delivery->roles,
            permissions: $delivery->permissions,
            metadata: $delivery->metadata,
            lifecycle: self::lifecycle($invitation),
            resendCount: $delivery->resendCount,
            lastSentAt: $invitation->last_sent_at,
            expiresAt: $delivery->expiresAt,
            acceptedAt: $invitation->accepted_at,
            revokedAt: $invitation->revoked_at,
            deliveryStatus: $invitation->delivery_status,
            deliveryAttemptedAt: $invitation->delivery_attempted_at,
            deliveredAt: $invitation->delivered_at,
            deliveryFailedAt: $invitation->delivery_failed_at,
            deliveryFailureCode: $invitation->delivery_failure_code,
        );
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

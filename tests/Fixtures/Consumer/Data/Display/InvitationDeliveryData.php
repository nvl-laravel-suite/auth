<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Bounded invitation context for host-owned delivery listeners.
 *
 * @api
 */
final class InvitationDeliveryData implements Arrayable, JsonSerializable
{
    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, bool|float|int|string|null>  $metadata
     */
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $purpose,
        public readonly string $recipient,
        public readonly ?AuthSubjectReferenceData $inviter,
        public readonly array $roles,
        public readonly array $permissions,
        public readonly array $metadata,
        public readonly CarbonImmutable $expiresAt,
        public readonly int $resendCount,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'purpose' => $this->purpose,
            'recipient' => $this->recipient,
            'inviter' => $this->inviter?->toArray(),
            'roles' => $this->roles,
            'permissions' => $this->permissions,
            'metadata' => $this->metadata,
            'expiresAt' => $this->expiresAt->format(DATE_ATOM),
            'resendCount' => $this->resendCount,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}

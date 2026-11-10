<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Exposes only tenant-safe membership and allowlisted principal identity fields.
 *
 * @api
 */
final class TenantMembershipData implements Arrayable, JsonSerializable
{
    public function __construct(
        public readonly string $id,
        public readonly ?string $tenantId,
        public readonly string $subjectType,
        public readonly string $subjectId,
        public readonly MembershipStatus $status,
        public readonly bool $owner,
        public readonly int $revision,
        public readonly ?string $name = null,
        public readonly ?string $email = null,
        public readonly ?OwnerReference $ownerReference = null,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'tenantId' => $this->tenantId,
            'subjectType' => $this->subjectType,
            'subjectId' => $this->subjectId,
            'status' => $this->status->value,
            'owner' => $this->owner,
            'revision' => $this->revision,
            'name' => $this->name,
            'email' => $this->email,
            'ownerReference' => $this->ownerReference?->toArray(),
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Consumer-safe result for a role canonical-name availability check.
 *
 * @api
 */
final class RoleNameAvailabilityData implements Arrayable, JsonSerializable
{
    /**
     * Create a role name availability result.
     */
    public function __construct(
        public readonly string $name,
        public readonly bool $available,
        public readonly ?string $conflictingRoleId,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'available' => $this->available,
            'conflictingRoleId' => $this->conflictingRoleId,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /** @param array<string, mixed> $attributes */
    public static function from(array $attributes): self
    {
        return new self(
            name: $attributes['name'],
            available: $attributes['available'],
            conflictingRoleId: $attributes['conflictingRoleId'],
        );
    }
}

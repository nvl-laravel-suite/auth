<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;
use JsonException;

/**
 * Carries one permission catalog entry.
 */
final readonly class PermissionData
{
    /**
     * Create permission input.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $name,
        public ?string $displayName = null,
        public ?string $description = null,
        public ?string $group = null,
        public bool $system = false,
        public array $metadata = [],
    ) {
        if (trim($this->name) === '' || mb_strlen($this->name) > 160) {
            throw new InvalidArgumentException('Permission names must contain between one and 160 characters.');
        }

        if ($this->displayName !== null && mb_strlen($this->displayName) > 160) {
            throw new InvalidArgumentException('Permission display names must not exceed 160 characters.');
        }

        if ($this->description !== null && mb_strlen($this->description) > 2_000) {
            throw new InvalidArgumentException('Permission descriptions must not exceed 2,000 characters.');
        }

        if ($this->group !== null && mb_strlen($this->group) > 120) {
            throw new InvalidArgumentException('Permission groups must not exceed 120 characters.');
        }

        try {
            $metadata = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Permission metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($metadata) > 65_535) {
            throw new InvalidArgumentException('Permission metadata must not exceed 65,535 encoded bytes.');
        }
    }
}

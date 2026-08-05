<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;
use JsonException;

/**
 * Carries role details and its canonical permission assignment.
 */
final readonly class RoleData
{
    /**
     * Create role input.
     *
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $name,
        public ?string $displayName = null,
        public ?string $description = null,
        public ?string $parentId = null,
        public int $priority = 0,
        public bool $system = false,
        public array $permissions = [],
        public array $metadata = [],
    ) {
        if (trim($this->name) === '' || mb_strlen($this->name) > 160) {
            throw new InvalidArgumentException('Role names must contain between one and 160 characters.');
        }

        if ($this->displayName !== null && mb_strlen($this->displayName) > 160) {
            throw new InvalidArgumentException('Role display names must not exceed 160 characters.');
        }

        if ($this->description !== null && mb_strlen($this->description) > 2_000) {
            throw new InvalidArgumentException('Role descriptions must not exceed 2,000 characters.');
        }

        if ($this->parentId !== null && ! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $this->parentId)) {
            throw new InvalidArgumentException('Role parent identifiers must be UUIDs.');
        }

        if ($this->priority < -100_000 || $this->priority > 100_000) {
            throw new InvalidArgumentException('Role priority must be between -100,000 and 100,000.');
        }

        if (count($this->permissions) > 500) {
            throw new InvalidArgumentException('Role permissions must be a list containing at most 500 values.');
        }

        $seen = [];

        foreach ($this->permissions as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('Role permission names must contain between one and 160 characters.');
            }

            if (isset($seen[$permission])) {
                throw new InvalidArgumentException('Role permission names must be distinct.');
            }

            $seen[$permission] = true;
        }

        try {
            $metadata = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Role metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($metadata) > 65_535) {
            throw new InvalidArgumentException('Role metadata must not exceed 65,535 encoded bytes.');
        }
    }
}

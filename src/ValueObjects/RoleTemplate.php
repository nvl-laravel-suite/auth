<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Data\Mutations\StoreRoleData;

/**
 * Defines one validated RBAC role template and its presentation metadata.
 */
final readonly class RoleTemplate
{
    /**
     * Create a validated role template.
     *
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $key,
        public array $permissions,
        public ?string $roleName = null,
        public ?string $displayName = null,
        public ?string $description = null,
        public bool $system = true,
        public ?string $parentRole = null,
        public int $priority = 0,
        public array $metadata = [],
    ) {
        if (trim($this->key) === '' || mb_strlen($this->key) > 160) {
            throw new InvalidArgumentException('Role template keys must contain between one and 160 characters.');
        }

        foreach ([$this->roleName, $this->displayName, $this->parentRole] as $name) {
            if ($name !== null && (trim($name) === '' || mb_strlen($name) > 160)) {
                throw new InvalidArgumentException('Role template names must contain between one and 160 characters.');
            }
        }

        if ($this->description !== null && mb_strlen($this->description) > 2_000) {
            throw new InvalidArgumentException('Role template descriptions must not exceed 2,000 characters.');
        }

        if ($this->priority < -100_000 || $this->priority > 100_000) {
            throw new InvalidArgumentException('Role template priority must be between -100,000 and 100,000.');
        }

        if (count($this->permissions) > 500 || count(array_unique($this->permissions)) !== count($this->permissions)) {
            throw new InvalidArgumentException('Role template permissions must be a distinct list containing at most 500 names.');
        }

        foreach ($this->permissions as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('Role template permission names must contain between one and 160 characters.');
            }
        }

        try {
            $encoded = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Role template metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($encoded) > 65_535) {
            throw new InvalidArgumentException('Role template metadata must not exceed 65,535 encoded bytes.');
        }
    }

    /**
     * Create the validated full role mutation represented by this template.
     */
    public function toMutation(?string $targetRoleName = null, ?string $parentId = null): StoreRoleData
    {
        return new StoreRoleData(
            name: $targetRoleName ?? $this->roleName ?? $this->key,
            displayName: $this->displayName,
            description: $this->description,
            parentId: $parentId,
            priority: $this->priority,
            system: $this->system,
            permissions: $this->permissions,
            metadata: $this->metadata,
        );
    }

    /**
     * Return the public template representation.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'roleName' => $this->roleName ?? $this->key,
            'displayName' => $this->displayName,
            'description' => $this->description,
            'system' => $this->system,
            'parentRole' => $this->parentRole,
            'priority' => $this->priority,
            'permissions' => $this->permissions,
            'metadata' => $this->metadata,
        ];
    }
}

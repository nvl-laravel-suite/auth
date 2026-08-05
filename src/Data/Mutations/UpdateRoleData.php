<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use InvalidArgumentException;
use JsonException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Support\Validation\ValidationContext;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated replacement mutation for one managed role. */
final class UpdateRoleData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $name,
        public readonly ?string $displayName = null,
        public readonly ?string $description = null,
        public readonly ?string $parentId = null,
        public readonly int $priority = 0,
        public readonly bool $system = false,
        public readonly array $permissions = [],
        public readonly array $metadata = [],
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
            $encodedMetadata = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Role metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($encodedMetadata) > 65_535) {
            throw new InvalidArgumentException('Role metadata must not exceed 65,535 encoded bytes.');
        }
    }

    /**
     * Validate and create a role mutation with server-resolved update context.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function validateForUpdate(array $payload, string $roleId): self
    {
        return self::validateAndCreate(array_replace($payload, [
            '_currentRoleId' => $roleId,
        ]));
    }

    /** @return array<string, list<mixed>> */
    public static function rules(?ValidationContext $context = null): array
    {
        $payload = is_array($context?->fullPayload) ? $context->fullPayload : [];
        $roleId = isset($payload['_currentRoleId']) && is_string($payload['_currentRoleId'])
            ? $payload['_currentRoleId']
            : null;
        $roles = Config::string('nvl-auth.tables.roles', 'nvl_auth_roles');
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique($roles, 'name')->where('guard_name', $guard)->ignore($roleId),
            ],
            'displayName' => ['nullable', 'string', 'max:160'],
            'description' => ['nullable', 'string', 'max:2000'],
            'parentId' => ['nullable', 'uuid', "exists:{$roles},id"],
            'priority' => ['sometimes', 'integer', 'between:-100000,100000'],
            'permissions' => ['sometimes', 'array', 'max:500'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
            'metadata' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

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
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated creation mutation for one managed permission. */
final class StorePermissionData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $name,
        public readonly ?string $displayName = null,
        public readonly ?string $description = null,
        public readonly ?string $group = null,
        public readonly bool $system = false,
        public readonly array $metadata = [],
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
            $encodedMetadata = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('Permission metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($encodedMetadata) > 65_535) {
            throw new InvalidArgumentException('Permission metadata must not exceed 65,535 encoded bytes.');
        }
    }

    /** @return array<string, list<mixed>> */
    public static function rules(): array
    {
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique($permissions, 'name')->where('guard_name', $guard),
            ],
            'displayName' => ['nullable', 'string', 'max:160'],
            'description' => ['nullable', 'string', 'max:2000'],
            'group' => ['nullable', 'string', 'max:120'],
            'metadata' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

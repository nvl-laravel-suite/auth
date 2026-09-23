<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/** Validated role-cloning input with the configured guard's uniqueness rule. */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class CloneRoleData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly string $name,
        public readonly ?string $displayName = null,
    ) {}

    /** @return array<string, mixed> */
    public static function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', AuthTables::Roles);
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => ['required', 'string', 'max:160', Rule::unique($roles, 'name')->where('guard_name', $guard)],
            'display_name' => ['nullable', 'string', 'max:160'],
        ];
    }
}

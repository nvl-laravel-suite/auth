<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** Validated role-cloning input with the configured guard's uniqueness rule. */
final class CloneRoleData
{
    public function __construct(
        public readonly string $name,
        public readonly ?string $displayName = null,
    ) {}

    /** @return array<string, mixed> */
    public static function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', AuthTables::get(AuthTables::Roles));
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => ['required', 'string', 'max:160', Rule::unique($roles, 'name')->where('guard_name', $guard)],
            'display_name' => ['nullable', 'string', 'max:160'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Nvl\Auth\Definitions\Tables\AuthTables;

/** Validates role cloning input. */
final class CloneRoleRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', AuthTables::Roles);
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => ['required', 'string', 'max:160', Rule::unique($roles, 'name')->where('guard_name', $guard)],
            'display_name' => ['nullable', 'string', 'max:160'],
        ];
    }
}

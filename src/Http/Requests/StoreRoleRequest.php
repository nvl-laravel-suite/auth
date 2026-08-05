<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

/** Validates role creation and update input. */
final class StoreRoleRequest extends FormRequest
{
    /** Defer management authorization to the Action. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', 'nvl_auth_roles');
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique($roles, 'name')->where('guard_name', $guard)->ignore($this->route('role')),
            ],
            'display_name' => ['nullable', 'string', 'max:160'],
            'description' => ['nullable', 'string', 'max:2000'],
            'parent_id' => ['nullable', 'uuid', "exists:{$roles},id"],
            'priority' => ['sometimes', 'integer', 'between:-100000,100000'],
            'permissions' => ['sometimes', 'array', 'max:500'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
            'metadata' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

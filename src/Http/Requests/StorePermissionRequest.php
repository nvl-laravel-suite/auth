<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;

/** Validates permission creation and update input. */
final class StorePermissionRequest extends FormRequest
{
    /** Defer management authorization to the Action. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');
        $guard = Config::string('nvl-auth.features.rbac.settings.guard', 'web');

        return [
            'name' => [
                'required',
                'string',
                'max:160',
                Rule::unique($permissions, 'name')->where('guard_name', $guard)->ignore($this->route('permission')),
            ],
            'display_name' => ['nullable', 'string', 'max:160'],
            'description' => ['nullable', 'string', 'max:2000'],
            'group' => ['nullable', 'string', 'max:120'],
            'metadata' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

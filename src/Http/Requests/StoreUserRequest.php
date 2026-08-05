<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rules\Password;

/** Validates principal creation transport input. */
final class StoreUserRequest extends FormRequest
{
    /** Allow the Action-owned management authorization check to decide access. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $users = Config::string('nvl-auth.tables.users', 'nvl_auth_users');
        $roles = Config::string('nvl-auth.tables.roles', 'nvl_auth_roles');
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');

        return [
            'name' => ['required', 'string', 'max:160'],
            'email' => ['required', 'email', 'max:254', "unique:{$users},email"],
            'password' => ['nullable', Password::min(12)->letters()->numbers()],
            'active' => ['sometimes', 'boolean'],
            'email_verified' => ['sometimes', 'boolean'],
            'locale' => ['sometimes', 'string', 'max:12'],
            'timezone' => ['sometimes', 'timezone:all'],
            'profile' => ['sometimes', 'array', 'max:100'],
            'preferences' => ['sometimes', 'array', 'max:100'],
            'roles' => ['sometimes', 'array', 'max:100'],
            'roles.*' => ['string', 'distinct', "exists:{$roles},name"],
            'permissions' => ['sometimes', 'array', 'max:250'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;

/** Validates partial principal mutation input. */
final class UpdateUserRequest extends FormRequest
{
    /** Defer business authorization to the Action. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $table = Config::string('nvl-auth.tables.users', 'nvl_auth_users');

        return [
            'name' => ['sometimes', 'string', 'max:160'],
            'email' => ['sometimes', 'email', 'max:254', Rule::unique($table, 'email')->ignore($this->route('user'))],
            'password' => ['sometimes', 'nullable', Password::min(12)->letters()->numbers()],
            'email_verified' => ['sometimes', 'boolean'],
            'locale' => ['sometimes', 'string', 'max:12'],
            'timezone' => ['sometimes', 'timezone:all'],
            'profile' => ['sometimes', 'array', 'max:100'],
            'preferences' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;

/** Validates one principal role assignment replacement. */
final class SyncUserRolesRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', 'nvl_auth_roles');

        return [
            'roles' => ['required', 'array', 'max:100'],
            'roles.*' => ['string', 'distinct', "exists:{$roles},name"],
        ];
    }
}

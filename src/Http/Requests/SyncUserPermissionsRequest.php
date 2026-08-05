<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Config;

/** Validates one principal direct permission assignment replacement. */
final class SyncUserPermissionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');

        return [
            'permissions' => ['required', 'array', 'max:250'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
        ];
    }
}

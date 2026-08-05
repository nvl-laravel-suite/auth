<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Nvl\Auth\Enums\UserBulkOperation;

/** Validates bounded bulk principal operations. */
final class BulkUserRequest extends FormRequest
{
    /** Defer management authorization to the Action. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'operation' => ['required', Rule::enum(UserBulkOperation::class)],
            'user_ids' => ['required', 'array', 'min:1', 'max:100'],
            'user_ids.*' => ['required', 'uuid', 'distinct'],
        ];
    }
}

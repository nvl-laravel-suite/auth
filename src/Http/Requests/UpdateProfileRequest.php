<?php

declare(strict_types=1);

namespace Nvl\Auth\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/** Validates self-service profile mutations. */
final class UpdateProfileRequest extends FormRequest
{
    /** Authenticated route middleware owns admission. */
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:160'],
            'locale' => ['required', 'string', 'max:12'],
            'timezone' => ['required', 'timezone:all'],
            'profile' => ['sometimes', 'array', 'max:100'],
            'preferences' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

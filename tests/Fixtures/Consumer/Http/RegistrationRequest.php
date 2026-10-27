<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Http;

use Illuminate\Foundation\Http\FormRequest;

/** Consumer-owned transport validation; the complete service retains domain validation. */
final class RegistrationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['name' => ['required', 'string'], 'email' => ['required', 'string'], 'password' => ['required', 'string'], 'passwordConfirmation' => ['required', 'string'], 'locale' => ['sometimes', 'string'], 'timezone' => ['sometimes', 'string'], 'extensions' => ['sometimes', 'array']];
    }
}

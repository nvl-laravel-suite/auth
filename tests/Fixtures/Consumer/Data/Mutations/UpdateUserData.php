<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\AuthRequestInput;

/**
 * Validated partial mutation for one managed principal.
 *
 * @api
 */
final class UpdateUserData
{
    /**
     * Validate and create a user mutation with server-resolved update context.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function validateForUpdate(array $payload, string $userId): array
    {
        $validated = Validator::make(AuthRequestInput::aliased($payload, ['emailVerified' => ['email_verified']]), self::rules($userId))->validate();

        if (array_key_exists('emailVerified', $validated)) {
            $validated['emailVerified'] = (bool) $validated['emailVerified'];
        }

        return $validated;
    }

    /**
     * Return validation rules for a principal update.
     *
     * @return array<string, list<mixed>>
     */
    public static function rules(?string $userId = null): array
    {
        $table = Config::string('nvl-auth.tables.users', AuthTables::get(AuthTables::Users));
        $id = Config::string('nvl-auth.features.principal_management.settings.attributes.id', 'id');
        $email = Config::string('nvl-auth.features.principal_management.settings.attributes.email', 'email');

        return [
            'name' => ['sometimes', 'string', 'max:160'],
            'email' => ['sometimes', 'email', 'max:254', Rule::unique($table, $email)->ignore($userId, $id)],
            'password' => ['sometimes', 'nullable', Password::min(12)->letters()->numbers()],
            'emailVerified' => ['sometimes', 'boolean'],
            'locale' => ['sometimes', 'string', 'max:12'],
            'timezone' => ['sometimes', 'timezone:all'],
            'profile' => ['sometimes', 'array', 'max:100'],
            'preferences' => ['sometimes', 'array', 'max:100'],
        ];
    }
}

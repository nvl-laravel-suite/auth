<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use DateTimeZone;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rules\Password;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated creation mutation for one managed principal. */
final class StoreUserData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>  $profile
     * @param  array<string, mixed>  $preferences
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        public readonly string $name,
        public readonly string $email,
        public readonly ?string $password,
        public readonly bool $active = true,
        public string $locale = 'en',
        public string $timezone = 'UTC',
        public readonly array $profile = [],
        public readonly array $preferences = [],
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly bool $emailVerified = false,
    ) {
        if (trim($this->name) === '' || mb_strlen($this->name) > 160) {
            throw new InvalidArgumentException('User names must contain between one and 160 characters.');
        }

        if (filter_var($this->email, FILTER_VALIDATE_EMAIL) === false || mb_strlen($this->email) > 254) {
            throw new InvalidArgumentException('A valid user email address is required.');
        }

        if ($this->password !== null && mb_strlen($this->password) < 12) {
            throw new InvalidArgumentException('User passwords must contain at least 12 characters.');
        }

        if (! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $this->locale)) {
            throw new InvalidArgumentException('A valid user locale is required.');
        }

        if (! in_array($this->timezone, DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid user timezone is required.');
        }

        $this->assertJsonPayloadIsBounded($this->profile, 'profile');
        $this->assertJsonPayloadIsBounded($this->preferences, 'preferences');
        $this->assertStringListIsBounded($this->roles, 100, 'roles');
        $this->assertStringListIsBounded($this->permissions, 250, 'permissions');
    }

    /**
     * Ensure a JSON-like user payload remains serializable and bounded.
     *
     * @param  array<string, mixed>  $payload
     */
    private function assertJsonPayloadIsBounded(array $payload, string $field): void
    {
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException("User {$field} must be JSON serializable.", previous: $exception);
        }

        if (strlen($encoded) > 65_535) {
            throw new InvalidArgumentException("User {$field} must not exceed 65,535 encoded bytes.");
        }
    }

    /**
     * Ensure a string list remains distinct and bounded.
     *
     * @param  list<string>  $values
     */
    private function assertStringListIsBounded(array $values, int $maximum, string $field): void
    {
        if (count($values) > $maximum) {
            throw new InvalidArgumentException("User {$field} must be a list containing at most {$maximum} values.");
        }

        $seen = [];
        foreach ($values as $value) {
            if (trim($value) === '' || mb_strlen($value) > 160) {
                throw new InvalidArgumentException("User {$field} values must contain between one and 160 characters.");
            }

            if (isset($seen[$value])) {
                throw new InvalidArgumentException("User {$field} values must be distinct.");
            }

            $seen[$value] = true;
        }
    }

    /** @return array<string, list<mixed>> */
    public static function rules(): array
    {
        $users = Config::string('nvl-auth.tables.users', AuthTables::Users);
        $email = Config::string('nvl-auth.features.principal_management.settings.attributes.email', 'email');
        $roles = Config::string('nvl-auth.tables.roles', AuthTables::Roles);
        $permissions = Config::string('nvl-auth.tables.permissions', AuthTables::Permissions);

        return [
            'name' => ['required', 'string', 'max:160'],
            'email' => ['required', 'email', 'max:254', "unique:{$users},{$email}"],
            'password' => ['nullable', Password::min(12)->letters()->numbers()],
            'active' => ['sometimes', 'boolean'],
            'emailVerified' => ['sometimes', 'boolean'],
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

<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use DateTimeZone;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use InvalidArgumentException;
use JsonException;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Optional;
use Spatie\LaravelData\Support\Validation\ValidationContext;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated partial mutation for one managed principal. */
final class UpdateUserData extends Data
{
    use DataTransform;

    /**
     * @param  array<string, mixed>|Optional  $profile
     * @param  array<string, mixed>|Optional  $preferences
     */
    public function __construct(
        public readonly string|Optional $name = new Optional,
        public readonly string|Optional $email = new Optional,
        public readonly string|Optional|null $password = new Optional,
        public string|Optional $locale = new Optional,
        public string|Optional $timezone = new Optional,
        public readonly array|Optional $profile = new Optional,
        public readonly array|Optional $preferences = new Optional,
        public readonly bool|Optional $emailVerified = new Optional,
    ) {
        if (is_string($this->name) && (trim($this->name) === '' || mb_strlen($this->name) > 160)) {
            throw new InvalidArgumentException('User names must contain between one and 160 characters.');
        }

        if (is_string($this->email)
            && (filter_var($this->email, FILTER_VALIDATE_EMAIL) === false || mb_strlen($this->email) > 254)) {
            throw new InvalidArgumentException('A valid user email address is required.');
        }

        if (is_string($this->password) && mb_strlen($this->password) < 12) {
            throw new InvalidArgumentException('User passwords must contain at least 12 characters.');
        }

        if (is_string($this->locale) && ! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $this->locale)) {
            throw new InvalidArgumentException('A valid user locale is required.');
        }

        if (is_string($this->timezone) && ! in_array($this->timezone, DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid user timezone is required.');
        }

        if (is_array($this->profile)) {
            $this->assertJsonPayloadIsBounded($this->profile, 'profile');
        }

        if (is_array($this->preferences)) {
            $this->assertJsonPayloadIsBounded($this->preferences, 'preferences');
        }
    }

    /**
     * Validate and create a user mutation with server-resolved update context.
     *
     * @param  array<string, mixed>  $payload
     */
    public static function validateForUpdate(array $payload, string $userId): self
    {
        return self::validateAndCreate(array_replace($payload, [
            '_currentUserId' => $userId,
        ]));
    }

    /**
     * Return validation rules for a principal update.
     *
     * @return array<string, list<mixed>>
     */
    public static function rules(?ValidationContext $context = null): array
    {
        $payload = is_array($context?->fullPayload) ? $context->fullPayload : [];
        $userId = isset($payload['_currentUserId']) && is_string($payload['_currentUserId'])
            ? $payload['_currentUserId']
            : null;
        $table = Config::string('nvl-auth.tables.users', AuthTables::Users);
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
}

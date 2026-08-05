<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use DateTimeZone;
use InvalidArgumentException;
use JsonException;

/**
 * Carries validated input for one package principal.
 */
final readonly class CreateUserData
{
    /**
     * Create principal input.
     *
     * @param  array<string, mixed>  $profile
     * @param  array<string, mixed>  $preferences
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        public string $name,
        public string $email,
        public ?string $password,
        public bool $active = true,
        public string $locale = 'en',
        public string $timezone = 'UTC',
        public array $profile = [],
        public array $preferences = [],
        public array $roles = [],
        public array $permissions = [],
        public bool $emailVerified = false,
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

    /** @param array<string, mixed> $payload */
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

    /** @param list<string> $values */
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
}

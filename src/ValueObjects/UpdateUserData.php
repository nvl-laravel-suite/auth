<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use DateTimeZone;
use InvalidArgumentException;
use JsonException;

/**
 * Carries a partial principal mutation with explicit nullable fields.
 */
final readonly class UpdateUserData
{
    /**
     * Create partial principal input.
     *
     * @param  array<string, mixed>|null  $profile
     * @param  array<string, mixed>|null  $preferences
     */
    public function __construct(
        public ?string $name = null,
        public ?string $email = null,
        public ?string $password = null,
        public ?string $locale = null,
        public ?string $timezone = null,
        public ?array $profile = null,
        public ?array $preferences = null,
        public ?bool $emailVerified = null,
    ) {
        if ($this->name !== null && (trim($this->name) === '' || mb_strlen($this->name) > 160)) {
            throw new InvalidArgumentException('User names must contain between one and 160 characters.');
        }

        if ($this->email !== null
            && (filter_var($this->email, FILTER_VALIDATE_EMAIL) === false || mb_strlen($this->email) > 254)) {
            throw new InvalidArgumentException('A valid user email address is required.');
        }

        if ($this->password !== null && mb_strlen($this->password) < 12) {
            throw new InvalidArgumentException('User passwords must contain at least 12 characters.');
        }

        if ($this->locale !== null && ! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $this->locale)) {
            throw new InvalidArgumentException('A valid user locale is required.');
        }

        if ($this->timezone !== null && ! in_array($this->timezone, DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid user timezone is required.');
        }

        if ($this->profile !== null) {
            $this->assertJsonPayloadIsBounded($this->profile, 'profile');
        }

        if ($this->preferences !== null) {
            $this->assertJsonPayloadIsBounded($this->preferences, 'preferences');
        }
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
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use DateTimeZone;
use InvalidArgumentException;
use JsonException;

/**
 * Carries self-service profile and preference changes.
 */
final readonly class ProfileData
{
    /**
     * Create profile input.
     *
     * @param  array<string, mixed>  $profile
     * @param  array<string, mixed>  $preferences
     */
    public function __construct(
        public string $name,
        public string $locale,
        public string $timezone,
        public array $profile = [],
        public array $preferences = [],
    ) {
        if (trim($this->name) === '' || mb_strlen($this->name) > 160) {
            throw new InvalidArgumentException('Profile names must contain between one and 160 characters.');
        }

        if (! preg_match('/^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8})*$/', $this->locale)) {
            throw new InvalidArgumentException('A valid profile locale is required.');
        }

        if (! in_array($this->timezone, DateTimeZone::listIdentifiers(), true)) {
            throw new InvalidArgumentException('A valid profile timezone is required.');
        }

        $this->assertJsonPayloadIsBounded($this->profile, 'profile');
        $this->assertJsonPayloadIsBounded($this->preferences, 'preferences');
    }

    /** @param array<string, mixed> $payload */
    private function assertJsonPayloadIsBounded(array $payload, string $field): void
    {
        try {
            $encoded = json_encode($payload, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException("Profile {$field} must be JSON serializable.", previous: $exception);
        }

        if (strlen($encoded) > 65_535) {
            throw new InvalidArgumentException("Profile {$field} must not exceed 65,535 encoded bytes.");
        }
    }
}

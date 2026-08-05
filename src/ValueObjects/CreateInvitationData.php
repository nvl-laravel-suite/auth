<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries validated input for one invitation issuance.
 */
final readonly class CreateInvitationData
{
    /**
     * Create invitation input.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $recipient,
        public string $type = 'registration',
        public string $purpose = 'registration',
        public array $roles = [],
        public array $permissions = [],
        public array $metadata = [],
        public ?string $locale = null,
    ) {
        if (trim($this->recipient) === '' || mb_strlen($this->recipient) > 320) {
            throw new InvalidArgumentException('Invitation recipients must contain between one and 320 characters.');
        }

        if (trim($this->type) === '' || mb_strlen($this->type) > 80
            || trim($this->purpose) === '' || mb_strlen($this->purpose) > 120) {
            throw new InvalidArgumentException('Invitation type or purpose is invalid.');
        }

        foreach ([...$this->roles, ...$this->permissions] as $grant) {
            if (! self::validGrant($grant)) {
                throw new InvalidArgumentException('Invitation role and permission names must be non-empty strings no longer than 255 characters.');
            }
        }

        $encodedMetadata = json_encode($this->metadata);

        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16_384) {
            throw new InvalidArgumentException('Invitation metadata must be JSON-serializable and no larger than 16 KiB.');
        }
    }

    /**
     * Determine whether an untrusted role or permission name is valid.
     */
    private static function validGrant(mixed $grant): bool
    {
        return is_string($grant) && trim($grant) !== '' && mb_strlen($grant) <= 255;
    }
}

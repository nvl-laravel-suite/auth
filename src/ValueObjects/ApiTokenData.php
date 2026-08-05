<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Carbon\CarbonImmutable;
use InvalidArgumentException;

/**
 * Carries validated personal access token input.
 */
final readonly class ApiTokenData
{
    /**
     * Create token input.
     *
     * @param  list<string>  $abilities
     */
    public function __construct(
        public string $name,
        public array $abilities,
        public ?CarbonImmutable $expiresAt = null,
    ) {
        if (trim($this->name) === '' || $this->name !== trim($this->name) || mb_strlen($this->name) > 120) {
            throw new InvalidArgumentException('API token name must contain between one and 120 characters.');
        }

        if ($this->abilities === []) {
            throw new InvalidArgumentException('API tokens require at least one ability.');
        }

        foreach ($this->abilities as $ability) {
            if (! self::validAbility($ability)) {
                throw new InvalidArgumentException('API token abilities must contain between one and 120 characters.');
            }
        }

        if (count(array_unique($this->abilities)) !== count($this->abilities)) {
            throw new InvalidArgumentException('API token abilities must be unique.');
        }

        if ($this->expiresAt instanceof CarbonImmutable && ! $this->expiresAt->isFuture()) {
            throw new InvalidArgumentException('API token expiry must be in the future.');
        }
    }

    /**
     * Determine whether an untrusted ability value is canonical.
     */
    private static function validAbility(mixed $ability): bool
    {
        return is_string($ability)
            && trim($ability) !== ''
            && $ability === trim($ability)
            && mb_strlen($ability) <= 120;
    }
}

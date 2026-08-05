<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * Identifies a host-owned authenticatable without projecting it into Auth storage.
 */
final readonly class SubjectReference
{
    /**
     * Create a host subject reference.
     */
    public function __construct(
        public string $type,
        public string $identifier,
    ) {
        if (trim($this->type) === ''
            || mb_strlen($this->type) > 160
            || trim($this->identifier) === ''
            || mb_strlen($this->identifier) > 191) {
            throw new InvalidArgumentException('Auth subject type or identifier is invalid.');
        }
    }

    /**
     * Resolve a reference from an authenticated host model.
     */
    public static function fromAuthenticatable(Authenticatable $subject): self
    {
        $type = $subject instanceof Model
            ? $subject->getMorphClass()
            : $subject::class;
        $identifier = $subject->getAuthIdentifier();

        if (! is_int($identifier) && ! is_string($identifier)) {
            throw new InvalidArgumentException('The authenticated subject must expose a scalar identifier.');
        }

        return new self($type, (string) $identifier);
    }
}

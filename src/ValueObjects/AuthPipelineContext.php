<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries typed use-case identity and bounded extension attributes.
 */
final readonly class AuthPipelineContext
{
    /**
     * Create a pipeline context.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(
        public string $name,
        public array $attributes = [],
        public ?SubjectReference $subject = null,
    ) {
        if (trim($this->name) === '') {
            throw new InvalidArgumentException('Auth pipeline names must be non-empty.');
        }
    }
}

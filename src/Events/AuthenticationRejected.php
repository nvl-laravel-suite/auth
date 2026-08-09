<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Publishes one rejected package authentication with a stable reason code.
 */
final class AuthenticationRejected
{
    use Dispatchable;

    /**
     * Create an authentication-rejection event.
     */
    public function __construct(
        public readonly string $identifierName,
        public readonly string $identifier,
        public readonly string $reason,
        public readonly ?SubjectReference $subject = null,
    ) {}
}

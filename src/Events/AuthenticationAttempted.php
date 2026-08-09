<?php

declare(strict_types=1);

namespace Nvl\Auth\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Publishes one package credential attempt without exposing the credential secret.
 */
final class AuthenticationAttempted
{
    use Dispatchable;

    /**
     * Create an authentication-attempt event.
     */
    public function __construct(
        public readonly string $identifierName,
        public readonly string $identifier,
    ) {}
}

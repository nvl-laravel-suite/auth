<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

/**
 * Carries optional transport context into authentication use cases.
 */
final readonly class AuthenticationRequestContext
{
    /**
     * Create bounded authentication request context.
     */
    public function __construct(
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        public ?string $requestId = null,
    ) {}
}

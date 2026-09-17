<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Tenancy\ValueObjects\TenantId;

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
        public ?string $tenantIntentNonce = null,
        public ?string $tenantSessionBinding = null,
        public ?TenantAuthenticationPurpose $tenantPurpose = null,
        public ?string $tenantProvider = null,
        public ?TenantId $requestedTenant = null,
        public bool $tenantIntentSubjectBound = false,
    ) {}
}

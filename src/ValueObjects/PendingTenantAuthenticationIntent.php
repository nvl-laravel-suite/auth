<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Nvl\Auth\Enums\TenantAuthenticationPurpose;

/**
 * Carries one server-owned post-authentication tenant-selection retry.
 */
final readonly class PendingTenantAuthenticationIntent
{
    /** Create an exact pending intent reference. */
    public function __construct(
        public SubjectReference $subject,
        public string $nonce,
        public string $sessionBinding,
        public TenantAuthenticationPurpose $purpose,
        public ?string $provider,
        public bool $subjectBound,
    ) {}
}

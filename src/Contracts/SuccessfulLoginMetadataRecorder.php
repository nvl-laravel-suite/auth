<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

/**
 * Persists host-specific metadata after successful authentication.
 */
interface SuccessfulLoginMetadataRecorder
{
    /**
     * Record successful-login metadata for one authenticated subject.
     */
    public function record(
        Authenticatable $subject,
        AuthenticationRequestContext $context,
    ): void;
}

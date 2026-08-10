<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use SensitiveParameter;

/**
 * Confirms a subject-controlled credential before sensitive self-service mutations.
 */
interface AccountConfirmation
{
    /** Require a valid subject confirmation credential. */
    public function assertConfirmed(Authenticatable $subject, #[SensitiveParameter] string $credential): void;
}

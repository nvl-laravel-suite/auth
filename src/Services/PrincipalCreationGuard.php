<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Forbids native inserts only during an existing-subject resolver invocation.
 * The scoped instance is always restored, including exceptions and nested calls.
 *
 * @internal
 */
final class PrincipalCreationGuard
{
    private int $prohibitions = 0;

    /** @template T
     * @param  Closure(): T  $operation
     * @return T
     */
    public function existingOnly(Closure $operation): mixed
    {
        $this->prohibitions++;
        try {
            return $operation();
        } finally {
            $this->prohibitions--;
        }
    }

    public function assertCreationAllowed(): void
    {
        if ($this->prohibitions > 0) {
            throw new AuthException('social_registration_unavailable', 'Verified social registration is not available yet.', 422);
        }
    }
}

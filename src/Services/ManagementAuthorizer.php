<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Applies the host's business authorization contract consistently.
 */
final readonly class ManagementAuthorizer
{
    /**
     * Create a management authorizer.
     */
    public function __construct(private AuthManagementAccess $access) {}

    /**
     * Require a package management ability.
     */
    public function authorize(
        Authenticatable $actor,
        string $ability,
        mixed $target = null,
    ): void {
        if (! $this->access->allows($actor, $ability, $target)) {
            throw new AuthException('forbidden', 'This Auth management operation is not authorized.', 403);
        }
    }
}

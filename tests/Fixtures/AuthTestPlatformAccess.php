<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Tenancy\Contracts\PlatformAccess;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;
use Nvl\Tenancy\ValueObjects\PlatformOperation;

/** Authorizes only the bounded Auth fixture's system operations. */
final class AuthTestPlatformAccess implements PlatformAccess
{
    /** Authorize the exact fixture operation namespace. */
    public function authorize(PlatformOperation $operation): void
    {
        if (! str_starts_with($operation->purpose, 'auth-test.')
            || $operation->actorType !== 'system'
            || $operation->actorId !== 'fixture') {
            throw new TenantBoundaryViolation('The Auth fixture platform operation is not authorized.');
        }
    }
}

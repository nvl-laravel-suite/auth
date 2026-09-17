<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Http\Request;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\ValueObjects\TenantId;

/**
 * Keeps disabled Auth HTTP routes injectable without selecting a tenant.
 */
final readonly class DisabledTenantHttpResolver implements TenantHttpResolver
{
    /** Reject accidental use outside the disabled-tenancy controller guard. */
    public function resolve(Request $request): TenantId
    {
        throw AuthException::invalidConfiguration('A tenant HTTP resolver is required when tenancy is enabled.');
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Illuminate\Http\Request;
use Nvl\Tenancy\Contracts\TenantHttpResolver;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Resolves only the fixture's signed-by-test tenant header. */
final class AuthTestTenantHttpResolver implements TenantHttpResolver
{
    public function resolve(Request $request): TenantId
    {
        $value = $request->header('X-Test-Tenant');
        if (! is_string($value) || ! in_array($value, [AuthTenancyScenario::A, AuthTenancyScenario::B], true)) {
            throw new TenantNotFound;
        }

        return new TenantId($value);
    }
}

<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;

it('keeps tenancy schema absent when Auth is installed without tenancy', function (): void {
    expect(config('tenancy.enabled'))->toBeFalse()
        ->and(config('nvl-auth.features.memberships.enabled'))->toBeFalse()
        ->and(Schema::hasTable('nvl_auth_tenant_memberships'))->toBeFalse()
        ->and(Schema::hasTable('nvl_tenancy_tenants'))->toBeFalse();
});

<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Nvl\Tenancy\Services\TenantAdoptionCoordinator;
use Nvl\Tenancy\ValueObjects\PlatformOperation;

it('reports the activated Auth tenancy boundary through named read-only checks', function (): void {
    $coordinator = app(TenantAdoptionCoordinator::class);
    $operation = new PlatformOperation('auth-test.adoption', 'system', 'fixture');
    $plan = $coordinator->prepare(['auth'], [], $operation);
    while (! $coordinator->backfill($plan, 100, $operation)) {
        // Empty adoption may still advance through bounded package phases.
    }
    $coordinator->activate($plan, $operation);

    Artisan::call('nvl:auth:doctor', ['--format' => 'json']);
    $report = json_decode(Artisan::output(), true, 64, JSON_THROW_ON_ERROR);
    $checks = collect($report['checks'])->keyBy('name');

    foreach ([
        'tenancy.membership_adapter',
        'tenancy.principal_resolver',
        'tenancy.connections',
        'tenancy.schema',
        'tenancy.marker',
        'tenancy.spatie_teams',
        'tenancy.no_null_roles',
        'tenancy.active_owners',
        'tenancy.invitation_proof',
        'tenancy.activity_bridge',
        'tenancy.scoped_context',
        'tenancy.global_clients',
    ] as $name) {
        expect($checks->has($name))->toBeTrue()
            ->and($checks->get($name)['passed'])->toBeTrue();
    }

    expect(Artisan::call('nvl:auth:prune', ['--dry-run' => true]))->toBe(2);
    Artisan::call('nvl:auth:schema', ['--format' => 'json']);
    $schema = json_decode(Artisan::output(), true, 64, JSON_THROW_ON_ERROR);
    expect($schema['outdated'])->toBe([]);
});

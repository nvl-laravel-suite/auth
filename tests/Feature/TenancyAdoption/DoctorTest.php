<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Nvl\Auth\Contracts\InvitationRecipientProof;
use Nvl\Auth\Contracts\TenantAwareAuthActivityBridge;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\DisabledInvitationRecipientProof;
use Nvl\Auth\Services\DisabledTenantAwareAuthActivityBridge;
use Nvl\Auth\Tests\Fixtures\RecordingTenantAwareAuthActivityBridge;
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

it('fails tenant readiness for disabled or mismatched configured integrations', function (): void {
    config()->set('nvl-auth.tenancy.activity_bridge', 'disabled');
    config()->set('nvl-auth.tenancy.recipient_proof', 'disabled');
    app()->forgetInstance(TenantAwareAuthActivityBridge::class);
    app()->forgetInstance(InvitationRecipientProof::class);

    Artisan::call('nvl:auth:doctor', ['--format' => 'json']);
    $checks = collect(json_decode(Artisan::output(), true, 64, JSON_THROW_ON_ERROR)['checks'])->keyBy('name');
    expect($checks->get('tenancy.activity_bridge')['passed'])->toBeFalse()
        ->and($checks->get('tenancy.invitation_proof')['passed'])->toBeFalse();

    config()->set('nvl-auth.tenancy.activity_bridge', RecordingTenantAwareAuthActivityBridge::class);
    app()->instance(TenantAwareAuthActivityBridge::class, new DisabledTenantAwareAuthActivityBridge);
    app()->instance(InvitationRecipientProof::class, new DisabledInvitationRecipientProof);
    Artisan::call('nvl:auth:doctor', ['--format' => 'json']);
    $checks = collect(json_decode(Artisan::output(), true, 64, JSON_THROW_ON_ERROR)['checks'])->keyBy('name');
    expect($checks->get('tenancy.activity_bridge')['passed'])->toBeFalse()
        ->and($checks->get('tenancy.invitation_proof')['passed'])->toBeFalse();
});

it('rejects invalid tenancy integration configuration values', function (): void {
    config()->set('nvl-auth.tenancy.activity_bridge', ['invalid']);
    app()->forgetInstance(TenantAwareAuthActivityBridge::class);
    expect(fn () => app(TenantAwareAuthActivityBridge::class))->toThrow(AuthException::class);

    config()->set('nvl-auth.tenancy.recipient_proof', stdClass::class);
    app()->forgetInstance(InvitationRecipientProof::class);
    expect(fn () => app(InvitationRecipientProof::class))->toThrow(AuthException::class);
});

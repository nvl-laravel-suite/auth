<?php

declare(strict_types=1);

use Illuminate\Support\Str;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Exceptions\TenantConfigurationInvalid;
use Nvl\Tenancy\Services\TenantAdoptionCoordinator;
use Nvl\Tenancy\ValueObjects\PlatformOperation;
use Nvl\Tenancy\ValueObjects\TenantAssignment;

it('maps a shared legacy role into reviewed tenant memberships', function (): void {
    $scenario = new AuthTenancyScenario;
    $one = $this->user('one@example.test');
    $two = $this->user('two@example.test');
    $source = Role::query()->create(['name' => 'manager', 'guard_name' => 'web']);
    $one->assignRole($source);
    $two->assignRole($source);
    $mappings = [];
    foreach ([[$one, $scenario->a()], [$two, $scenario->b()]] as [$principal, $tenant]) {
        $roleId = (string) Str::uuid();
        $reference = SubjectReference::fromAuthenticatable($principal);
        $mappings[] = new TenantAssignment('auth.roles', $roleId, $tenant, [
            'source_id' => $source->id,
            'parent_destination_id' => null,
        ]);
        $mappings[] = new TenantAssignment('auth.memberships', (string) Str::uuid(), $tenant, [
            'subject_type' => $reference->type,
            'subject_id' => $reference->identifier,
            'status' => 'active',
            'is_owner' => true,
            'role_ids' => [$roleId],
            'permission_ids' => [],
        ]);
    }
    $coordinator = app(TenantAdoptionCoordinator::class);
    $operation = new PlatformOperation('auth-test.adoption', 'system', 'fixture');
    $plan = $coordinator->prepare(['auth'], $mappings, $operation);
    while (! $coordinator->backfill($plan, 1, $operation)) {
        // Exercise resumable single-row checkpoints.
    }

    expect($coordinator->verify($plan)->errors)->toBe([]);
    $coordinator->activate($plan, $operation);
    app(TenantMembershipAccess::class)->assertMember($one, $scenario->a());
    app(TenantMembershipAccess::class)->assertMember($two, $scenario->b());
    expect($scenario->run($scenario->a(), fn () => $one->fresh()->hasRole('manager')))->toBeTrue()
        ->and($scenario->run($scenario->b(), fn () => $one->fresh()->hasRole('manager')))->toBeFalse();
});

it('resumes an immutable run without duplicating adopted rows', function (): void {
    $scenario = new AuthTenancyScenario;
    $principal = $this->user('resume@example.test');
    $source = Role::query()->create(['name' => 'reviewer', 'guard_name' => 'web']);
    $principal->assignRole($source);
    $roleId = (string) Str::uuid();
    $reference = SubjectReference::fromAuthenticatable($principal);
    $mappings = [
        new TenantAssignment('auth.roles', $roleId, $scenario->a(), [
            'source_id' => $source->id,
            'parent_destination_id' => null,
        ]),
        new TenantAssignment('auth.memberships', (string) Str::uuid(), $scenario->a(), [
            'subject_type' => $reference->type,
            'subject_id' => $reference->identifier,
            'status' => 'active',
            'is_owner' => true,
            'role_ids' => [$roleId],
            'permission_ids' => [],
        ]),
    ];
    $coordinator = app(TenantAdoptionCoordinator::class);
    $operation = new PlatformOperation('auth-test.adoption', 'system', 'fixture');
    $plan = $coordinator->prepare(['auth'], $mappings, $operation);
    expect($coordinator->backfill($plan, 1, $operation))->toBeFalse();
    $resumed = $coordinator->resume($plan->id);
    while (! $coordinator->backfill($resumed, 1, $operation)) {
        // Exercise persisted phase checkpoints after reconstructing the plan.
    }

    expect(app('db')->table(AuthTables::TenantMemberships)->count())->toBe(1)
        ->and(app('db')->table(AuthTables::Roles)->where('tenant_id', $scenario->a()->value)->count())->toBe(1)
        ->and(app('db')->table(AuthTables::ModelHasRoles)->where('tenant_id', $scenario->a()->value)->count())->toBe(1);

    config(['tenancy.profile' => 'changed-after-review']);
    expect(fn () => $coordinator->resume($plan->id))->toThrow(TenantConfigurationInvalid::class);
});

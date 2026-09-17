<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Services\TenantAdoptionCoordinator;
use Nvl\Tenancy\ValueObjects\PlatformOperation;

/** Run the complete empty Auth adoption under the explicit test operation. */
function activateAuthSchema(): void
{
    $coordinator = app(TenantAdoptionCoordinator::class);
    $operation = new PlatformOperation('auth-test.adoption', 'system', 'fixture');
    $plan = $coordinator->prepare(['auth'], [], $operation);
    while (! $coordinator->backfill($plan, 100, $operation)) {
        // Empty fixture adoption must complete in a bounded batch.
    }
    expect($coordinator->verify($plan)->passed())->toBeTrue();
    $coordinator->activate($plan, $operation);
}

it('keeps the independently selected schema absent before adoption', function (): void {
    expect(Schema::hasTable(AuthTables::TenantMemberships))->toBeFalse()
        ->and(Schema::hasColumn(AuthTables::Roles, 'tenant_id'))->toBeFalse();
});

it('selects tenancy schema after the legacy Auth migrations ran', function (): void {
    activateAuthSchema();

    expect(Schema::hasTable(AuthTables::TenantMemberships))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::TenantMembershipLocks))->toBeTrue()
        ->and(Schema::hasTable(AuthTables::TenantAuthenticationIntents))->toBeTrue()
        ->and(Schema::hasColumns(AuthTables::Invitations, ['tenant_id', 'ownership_key']))->toBeTrue();
});

it('enforces one membership per principal and tenant', function (): void {
    activateAuthSchema();
    $scenario = new AuthTenancyScenario;
    $subject = SubjectReference::fromAuthenticatable($this->user());
    $scenario->member($scenario->a(), $subject);
    $scenario->member($scenario->b(), $subject);

    expect(fn () => $scenario->member($scenario->a(), $subject))->toThrow(QueryException::class);
});

it('accepts the same role name in two tenants only after activation', function (): void {
    activateAuthSchema();
    $scenario = new AuthTenancyScenario;
    Role::query()->create(['tenant_id' => $scenario->a()->value, 'name' => 'manager', 'guard_name' => 'web']);
    Role::query()->create(['tenant_id' => $scenario->b()->value, 'name' => 'manager', 'guard_name' => 'web']);

    expect(Role::query()->where('name', 'manager')->count())->toBe(2);
});

it('rejects null final membership ownership', function (): void {
    activateAuthSchema();

    expect(fn () => app('db')->table(AuthTables::TenantMemberships)->insert([
        'id' => fake()->uuid(),
        'tenant_id' => null,
        'subject_type' => 'fixture',
        'subject_id' => 'one',
        'status' => 'active',
        'is_owner' => false,
        'revision' => 1,
        'created_at' => now(),
        'updated_at' => now(),
    ]))->toThrow(QueryException::class);
});

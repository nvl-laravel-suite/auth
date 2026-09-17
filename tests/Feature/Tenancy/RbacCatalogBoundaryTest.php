<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Rbac\BootstrapRbacAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionWithRolesAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\DeletePermissionAction;
use Nvl\Auth\Actions\Rbac\ShowPermissionAction;
use Nvl\Auth\Actions\Rbac\SynchronizePermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRbacAction;
use Nvl\Auth\Actions\Rbac\UpdatePermissionAction;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Data\Mutations\UpdatePermissionData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Services\AuthModelRegistry;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Services\RbacEntityLocator;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Tenancy\Exceptions\TenantBoundaryViolation;

it('projects global vocabulary roles only from the active tenant', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('rbac-catalog@example.test');
    $reference = SubjectReference::fromAuthenticatable($actor);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);
    $permission = $scenario->platform(fn () => Permission::query()->create(['name' => 'catalog.read', 'guard_name' => 'web']));
    foreach ([$scenario->a(), $scenario->b()] as $tenant) {
        $scenario->run($tenant, fn () => app(CreateRoleAction::class)->execute($actor, new StoreRoleData(
            name: 'reader',
            permissions: ['catalog.read'],
        )));
    }

    foreach ([$scenario->a(), $scenario->b()] as $tenant) {
        $scenario->run($tenant, function () use ($actor, $permission, $tenant): void {
            $projection = app(ShowPermissionAction::class)->execute($actor, $permission->id);
            expect($projection->roles)->toHaveCount(1)
                ->and($projection->roles->sole()->tenant_id)->toBe($tenant->value);
        });
    }
});

it('fails closed when directly constructed tenant RBAC services lack their collaborator', function (): void {
    $actor = $this->user('missing-rbac-collaborator@example.test');
    $models = app(AuthModelRegistry::class);

    foreach ([
        fn () => (new EloquentRbacPrincipalAccess($models))->find($actor),
        fn () => (new RbacEntityLocator($models))->permission('missing'),
    ] as $operation) {
        expect($operation)->toThrow(AuthException::class);
    }
});

it('rejects every platform permission vocabulary mutation from a permissive tenant actor', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('permission-boundary@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);
    [$updated, $deleted] = $scenario->platform(fn (): array => [
        Permission::query()->create(['name' => 'catalog.update', 'guard_name' => 'web']),
        Permission::query()->create(['name' => 'catalog.delete', 'guard_name' => 'web']),
    ]);

    $scenario->run($scenario->a(), function () use ($actor, $deleted, $updated): void {
        foreach ([
            fn () => app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('catalog.create')),
            fn () => app(UpdatePermissionAction::class)->execute($actor, $updated, new UpdatePermissionData('catalog.updated')),
            fn () => app(DeletePermissionAction::class)->execute($actor, $deleted),
            fn () => app(SynchronizePermissionCatalogAction::class)->execute($actor),
        ] as $operation) {
            expect($operation)->toThrow(TenantBoundaryViolation::class);
        }
    });

    expect(Permission::query()->where('name', 'catalog.create')->exists())->toBeFalse()
        ->and($updated->refresh()->name)->toBe('catalog.update')
        ->and($deleted->refresh()->exists)->toBeTrue();
});

it('rejects legacy mixed RBAC entry points whenever tenancy is enabled', function (): void {
    $scenario = new AuthTenancyScenario;
    $actor = $this->user('mixed-rbac@example.test');
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);

    $scenario->run($scenario->a(), function () use ($actor): void {
        foreach ([
            fn () => app(BootstrapRbacAction::class)->execute(new SystemMutationContext('test', 'mixed-bootstrap', $actor)),
            fn () => app(SynchronizeRbacAction::class)->execute($actor),
            fn () => app(CreatePermissionWithRolesAction::class)->execute($actor, new StorePermissionData('catalog.mixed')),
        ] as $operation) {
            try {
                $operation();
                $this->fail('The mixed RBAC operation was not rejected.');
            } catch (AuthException $exception) {
                expect($exception->errorCode)->toBe('rbac_mixed_context_operation');
            }
        }
    });
});

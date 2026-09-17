<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\ShowPermissionAction;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

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

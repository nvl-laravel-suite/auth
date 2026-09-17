<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;

it('restores tenant RBAC on the same retained principal', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $scenario->member($scenario->a(), $reference, true);
    $scenario->member($scenario->b(), $reference, true);
    $scenario->platform(fn () => Permission::query()->create(['name' => 'documents.write', 'guard_name' => 'web']));

    foreach ([$scenario->a(), $scenario->b()] as $tenant) {
        $scenario->run($tenant, function () use ($scenario, $tenant, $user): void {
            app(CreateRoleAction::class)->execute($user, new StoreRoleData(
                name: 'manager',
                permissions: $tenant->value === $scenario->a()->value ? ['documents.write'] : [],
            ));
            app(SyncUserRolesAction::class)->execute($user, $user, new SyncUserRolesData(['manager']));
        });
    }

    $scenario->run($scenario->a(), function () use ($scenario, $user): void {
        expect($user->can('documents.write'))->toBeTrue();
        $scenario->run($scenario->b(), fn () => expect($user->can('documents.write'))->toBeFalse());
        expect($user->can('documents.write'))->toBeTrue();
    });
});

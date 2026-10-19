<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Data\Mutations\StoreRoleData;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;
use Nvl\Auth\Tests\HostPolicyOwnerScopeTestCase;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Company;

uses(HostPolicyOwnerScopeTestCase::class);

it('uses a host admission policy without NVL membership or tenant tables', function (): void {
    $this->app->bind(OwnerAccess::class, static fn () => new class implements OwnerAccess
    {
        public function assertCanEnter(Authenticatable $actor, Model $owner): void {}
    });
    $user = User::factory()->create();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), $user, function () use ($user): void {
        $role = app(CreateRoleAction::class)->execute($user, new StoreRoleData('host-editor'));
        app(EloquentRbacPrincipalAccess::class)->assign($user, [$role->id], []);
        expect($user->fresh()->hasRole('host-editor'))->toBeTrue();
    });
    $schema = (new User)->getConnection()->getSchemaBuilder();
    expect($schema->hasTable('nvl_auth_owner_memberships'))->toBeFalse()
        ->and($schema->hasTable('nvl_auth_tenant_memberships'))->toBeFalse();
});

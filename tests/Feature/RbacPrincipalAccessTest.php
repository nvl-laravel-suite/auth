<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\EloquentRbacPrincipalAccess;

it('exposes the complete configured Eloquent RBAC principal adapter', function (): void {
    $role = Role::query()->create([
        'name' => 'consumer-manager',
        'guard_name' => 'web',
    ]);
    $permission = Permission::query()->create([
        'name' => 'consumer.read',
        'guard_name' => 'web',
    ]);
    $principal = $this->user('rbac-consumer@example.test');
    $access = new EloquentRbacPrincipalAccess;

    expect($access->find($principal))->toBe($principal)
        ->and($access->find((string) $principal->getKey())->is($principal))->toBeTrue()
        ->and($access->identifier($principal))->toBe((string) $principal->getKey())
        ->and($access->connectionName($principal))->toBe('testing');

    $access->assign($principal, [$role->name], [$permission->name]);
    expect($principal->hasRole($role))->toBeTrue()
        ->and($principal->hasPermissionTo($permission))->toBeTrue();

    $access->assign($principal, [], []);
    $access->syncRoles($principal, []);
    $access->syncPermissions($principal, []);
    $refreshed = $access->refresh($principal, ['roles', 'permissions']);

    expect($refreshed->relationLoaded('roles'))->toBeTrue()
        ->and($refreshed->relationLoaded('permissions'))->toBeTrue();
});

it('fails closed for invalid RBAC principal models and identifiers', function (): void {
    $access = new EloquentRbacPrincipalAccess;
    $generic = new GenericUser(['id' => 'generic-user']);

    expect(static fn () => $access->find($generic))
        ->toThrow(AuthException::class, 'using Spatie Permission HasRoles');

    config()->set('nvl-auth.features.rbac.models.principal', stdClass::class);
    expect(static fn () => $access->find('missing'))
        ->toThrow(AuthException::class, 'Eloquent Authenticatable model');

    $invalidIdentifier = new GenericUser(['id' => []]);
    expect(static fn (): string => $access->identifier($invalidIdentifier))
        ->toThrow(AuthException::class, 'string-compatible identifier');
});

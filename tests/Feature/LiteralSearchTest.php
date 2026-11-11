<?php

declare(strict_types=1);

use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthRbacReader;
use Nvl\Auth\Services\AuthUserReader;

it('matches role search text literally instead of as LIKE wildcards', function (): void {
    $actor = $this->user('search.roles@example.test');
    Role::query()->create(['name' => 'ops_lead', 'guard_name' => 'web']);
    Role::query()->create(['name' => 'opsxlead', 'guard_name' => 'web']);
    Role::query()->create(['name' => 'half%done', 'guard_name' => 'web']);
    $reader = app(AuthRbacReader::class);

    expect($reader->roles($actor, 'ops_')->pluck('name')->all())->toBe(['ops_lead'])
        ->and($reader->roleCatalog($actor, ['search' => 'ops_'])->pluck('name')->all())->toBe(['ops_lead'])
        ->and($reader->roleOptions($actor, 'ops_')->pluck('name')->all())->toBe(['ops_lead'])
        ->and($reader->suggestRoles($actor, 'ops_')->pluck('name')->all())->toBe(['ops_lead'])
        ->and($reader->roles($actor, '%')->pluck('name')->all())->toBe(['half%done'])
        ->and($reader->roleCatalog($actor, ['search' => '%'])->pluck('name')->all())->toBe(['half%done'])
        ->and($reader->roleOptions($actor, '%')->pluck('name')->all())->toBe(['half%done'])
        ->and($reader->roles($actor, 'ops!')->total())->toBe(0);
});

it('matches permission search text literally instead of as LIKE wildcards', function (): void {
    $actor = $this->user('search.permissions@example.test');
    Permission::query()->create(['name' => 'report_read', 'guard_name' => 'web', 'group' => 'reports']);
    Permission::query()->create(['name' => 'reportxread', 'guard_name' => 'web', 'group' => 'reports']);
    Permission::query()->create(['name' => 'quota%raise', 'guard_name' => 'web', 'group' => 'reports']);
    $reader = app(AuthRbacReader::class);

    expect($reader->permissions($actor, 'report_')->pluck('name')->all())->toBe(['report_read'])
        ->and($reader->permissionCatalog($actor, ['search' => 'report_'])->pluck('name')->all())->toBe(['report_read'])
        ->and($reader->permissionOptions($actor, 'report_')->pluck('name')->all())->toBe(['report_read'])
        ->and($reader->suggestPermissions($actor, 'report_')->pluck('name')->all())->toBe(['report_read'])
        ->and($reader->permissions($actor, '%')->pluck('name')->all())->toBe(['quota%raise'])
        ->and($reader->permissionCatalog($actor, ['search' => '%'])->pluck('name')->all())->toBe(['quota%raise'])
        ->and($reader->permissionOptions($actor, '%')->pluck('name')->all())->toBe(['quota%raise']);
});

it('matches principal search text literally instead of as LIKE wildcards', function (): void {
    $actor = $this->user('searchactor@example.test');
    $this->user('first_last@example.test');
    $this->user('firstxlast@example.test');
    $reader = app(AuthUserReader::class);

    expect($reader->paginate($actor, 'first_')->pluck('email')->all())->toBe(['first_last@example.test'])
        ->and($reader->suggest($actor, 'first_')->pluck('email')->all())->toBe(['first_last@example.test'])
        ->and($reader->paginate($actor, '%')->total())->toBe(0)
        ->and($reader->suggest($actor, '%'))->toHaveCount(0);
});

it('rejects oversized compatibility role and permission filters before querying', function (): void {
    $actor = $this->user('search.bounds@example.test');
    $reader = app(AuthRbacReader::class);

    expect(fn () => $reader->roles($actor, str_repeat('a', 161)))->toThrow(AuthException::class, '160 characters')
        ->and(fn () => $reader->permissions($actor, str_repeat('a', 161)))->toThrow(AuthException::class, '160 characters')
        ->and(fn () => $reader->permissions($actor, null, str_repeat('g', 121)))->toThrow(AuthException::class, '120 characters')
        ->and($reader->roles($actor, str_repeat('a', 160))->total())->toBe(0);
});

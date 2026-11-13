<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Tests\Fixtures\HostAnalyticsPrincipal;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

it('preserves host auth and permission configuration with and without former adoption flags', function (): void {
    expect(config('auth'))->toBe($this->hostAuth)
        ->and(config('permission'))->toBe($this->hostPermission)
        ->and(config('nvl-auth.routes.enabled'))->toBeNull()
        ->and(config('nvl-auth.features.rbac.enabled'))->toBeFalse();

    $adoption = config('nvl-auth.adoption');
    $principal = ['enabled' => true, 'guard' => 'web', 'provider' => 'users'];
    $broker = ['enabled' => true, 'broker' => 'users'];
    foreach ([
        'both flags' => ['principal_model' => $principal, 'password_broker' => $broker],
        'broker only' => ['password_broker' => $broker],
        'incomplete principal' => ['principal_model' => ['enabled' => true]],
    ] as $scenario => $flags) {
        config(['nvl-auth.adoption' => array_replace($adoption, $flags)]);
        (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class));
        expect(config('auth'))->toBe($this->hostAuth, $scenario)
            ->and(config('permission'))->toBe($this->hostPermission, $scenario);
    }
});

it('adopts Spatie storage independently and retains readiness only for the current scope', function (): void {
    config(['nvl-auth.adoption.spatie_storage.enabled' => true]);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class));
    expect(config('auth'))->toBe($this->hostAuth)
        ->and(config('permission.table_names.roles'))->toBe(AuthTables::get(AuthTables::Roles));
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class);
    foreach ([AuthTables::Roles, AuthTables::Permissions, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions, AuthTables::RoleHasPermissions] as $table) {
        Schema::create(AuthTables::get($table), fn (Blueprint $blueprint) => $blueprint->uuid('id'));
    }
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class);
    app()->forgetScopedInstances();

    DB::enableQueryLog();
    expect(app(PermissionRegistrar::class)->teams)->toBeFalse();
    $initialQueries = count(DB::getQueryLog());
    app(PermissionRegistrar::class);
    app(PermissionRegistrar::class);
    expect(DB::getQueryLog())->toHaveCount($initialQueries);
    app()->forgetScopedInstances();
    app(PermissionRegistrar::class);
    expect(count(DB::getQueryLog()))->toBeGreaterThan($initialQueries);
});

it('denies permission resolution when adopted storage readiness cannot be established', function (): void {
    config(['nvl-auth.adoption.spatie_storage.enabled' => true, 'nvl-auth.connection' => 'unavailable_auth_storage']);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class));
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class, 'readiness');
    expect(config('permission.teams'))->toBeTrue();
});

it('ignores unselected adoption targets when reporting preserved host ownership', function (): void {
    config([
        'nvl-auth.adoption.principal_model.provider' => ['unused-host-value'],
        'nvl-auth.adoption.password_broker.broker' => ['unused-host-value'],
    ]);
    $checks = collect(app(AuthDoctor::class)->inspect())->keyBy('name');

    expect($checks->has('configuration.auth_provider'))->toBeFalse()
        ->and($checks->has('adoption.principal_model'))->toBeFalse()
        ->and($checks->has('adoption.password_broker'))->toBeFalse()
        ->and($checks['adoption.spatie_storage']['passed'])->toBeTrue()
        ->and(config('auth'))->toBe($this->hostAuth);
});

it('preserves actual host-user team authorization without Spatie storage adoption', function (): void {
    Schema::create('host_analytics_principals', function (Blueprint $table): void {
        $table->uuid('id')->primary();
        $table->string('name');
        $table->string('email');
        $table->timestamps();
    });
    Schema::create('host_roles', function (Blueprint $table): void {
        $table->id();
        $table->string('host_team_id')->nullable();
        $table->string('name');
        $table->string('guard_name');
        $table->timestamps();
    });
    Schema::create('host_permissions', function (Blueprint $table): void {
        $table->id();
        $table->string('name');
        $table->string('guard_name');
        $table->timestamps();
    });
    Schema::create('host_role_has_permissions', function (Blueprint $table): void {
        $table->unsignedBigInteger('role_id');
        $table->unsignedBigInteger('permission_id');
    });
    foreach (['host_model_has_roles' => 'role_id', 'host_model_has_permissions' => 'permission_id'] as $tableName => $key) {
        Schema::create($tableName, function (Blueprint $table) use ($key): void {
            $table->unsignedBigInteger($key);
            $table->uuid('model_id');
            $table->string('model_type');
            $table->string('host_team_id');
        });
    }
    $registrar = app(PermissionRegistrar::class);
    $registrar->setPermissionsTeamId('team-a');
    $role = Role::query()->create(['name' => 'host-editor', 'guard_name' => 'web', 'host_team_id' => 'team-a']);
    $permission = Permission::query()->create(['name' => 'host.reports', 'guard_name' => 'web']);
    $role->givePermissionTo($permission);
    $principal = HostAnalyticsPrincipal::query()->create(['name' => 'Host User', 'email' => 'host@example.test']);
    $principal->assignRole($role);
    expect($principal->can('host.reports'))->toBeTrue();
    $registrar->setPermissionsTeamId('team-b');
    $principal->unsetRelation('roles')->unsetRelation('permissions');
    expect($principal->can('host.reports'))->toBeFalse()
        ->and(config('auth'))->toBe($this->hostAuth)
        ->and(config('permission'))->toBe($this->hostPermission);
});

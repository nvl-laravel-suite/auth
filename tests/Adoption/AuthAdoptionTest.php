<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Definitions\Tables\AuthTables;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Tests\Fixtures\HostAnalyticsPrincipal;
use Nvl\Data\Services\TypeScriptSourceRegistry;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

it('preserves complete host auth and permission configuration on default installation', function (): void {
    expect(config('auth'))->toBe($this->hostAuth)
        ->and(config('permission'))->toBe($this->hostPermission)
        ->and(config('nvl-auth.routes.enabled'))->toBeFalse();
});

it('adopts only an explicitly targeted principal model', function (): void {
    config(['nvl-auth.adoption.principal_model' => ['enabled' => true, 'guard' => 'web', 'provider' => 'users']]);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class));
    $expected = $this->hostAuth;
    $expected['providers']['users']['model'] = User::class;
    expect(config('auth'))->toBe($expected)
        ->and(config('permission'))->toBe($this->hostPermission);
});

it('adopts password storage independently of principal and permission ownership', function (): void {
    config(['nvl-auth.adoption.password_broker' => ['enabled' => true, 'broker' => 'users']]);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class));
    $expected = $this->hostAuth;
    $expected['passwords']['users']['table'] = AuthTables::get(AuthTables::PasswordResetTokens);
    $expected['passwords']['users']['connection'] = config('database.default');
    expect(config('auth'))->toBe($expected)
        ->and(config('permission'))->toBe($this->hostPermission);
});

it('rejects principal adoption without an explicit matching guard and provider', function (): void {
    config(['nvl-auth.adoption.principal_model.enabled' => true]);
    expect(fn () => (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class)))
        ->toThrow(AuthException::class, 'explicit guard and provider');
});

it('adopts Spatie storage independently and memoizes readiness per scope', function (): void {
    foreach ([AuthTables::Roles, AuthTables::Permissions, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions, AuthTables::RoleHasPermissions] as $table) {
        Schema::create(AuthTables::get($table), fn (Blueprint $blueprint) => $blueprint->uuid('id'));
    }
    config(['nvl-auth.adoption.spatie_storage.enabled' => true]);
    $provider = new AuthServiceProvider(app());
    $provider->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class));
    expect(config('auth'))->toBe($this->hostAuth)
        ->and(config('permission.table_names.roles'))->toBe(AuthTables::get(AuthTables::Roles));
    DB::enableQueryLog();
    app(PermissionRegistrar::class);
    $initialQueries = count(DB::getQueryLog());
    for ($resolution = 0; $resolution < 18; $resolution++) {
        app(PermissionRegistrar::class);
    }
    expect(count(DB::getQueryLog()))->toBe($initialQueries);
    app()->forgetScopedInstances();
    app(PermissionRegistrar::class);
    expect(count(DB::getQueryLog()))->toBeGreaterThan($initialQueries);
});

it('denies permission resolution when adopted storage readiness cannot be established', function (): void {
    config(['nvl-auth.adoption.spatie_storage.enabled' => true, 'nvl-auth.connection' => 'unavailable_auth_storage']);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class));
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class, 'readiness');
    expect(config('permission.teams'))->toBeTrue();
});

it('recovers adopted readiness only after a lifecycle reset', function (): void {
    config(['nvl-auth.adoption.spatie_storage.enabled' => true]);
    (new AuthServiceProvider(app()))->boot(app(AuthConfiguration::class), app(TypeScriptSourceRegistry::class));
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class);
    foreach ([AuthTables::Roles, AuthTables::Permissions, AuthTables::ModelHasRoles, AuthTables::ModelHasPermissions, AuthTables::RoleHasPermissions] as $table) {
        Schema::create(AuthTables::get($table), fn (Blueprint $blueprint) => $blueprint->uuid('id'));
    }
    expect(fn () => app(PermissionRegistrar::class))->toThrow(AuthException::class);
    app()->forgetScopedInstances();
    expect(app(PermissionRegistrar::class)->teams)->toBeFalse();
});

it('describes intentional host ownership without requiring a package auth provider', function (): void {
    $checks = collect(app(AuthDoctor::class)->inspect())->keyBy('name');
    expect($checks->has('configuration.auth_provider'))->toBeFalse()
        ->and($checks['adoption.principal_model']['severity'])->toBe('info')
        ->and($checks['adoption.principal_model']['message'])->toContain('host')
        ->and($checks['adoption.spatie_storage']['passed'])->toBeTrue();
});

it('ignores unselected adoption targets when reporting preserved host ownership', function (): void {
    config([
        'nvl-auth.adoption.principal_model.provider' => ['unused-host-value'],
        'nvl-auth.adoption.password_broker.broker' => ['unused-host-value'],
    ]);
    $checks = collect(app(AuthDoctor::class)->inspect())->keyBy('name');

    expect($checks['adoption.principal_model']['message'])->toContain('disabled')
        ->and($checks['adoption.password_broker']['message'])->toContain('disabled')
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

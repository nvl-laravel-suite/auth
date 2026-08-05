<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Providers\RouteServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;

it('serves configurable principal profile and RBAC APIs without Inertia', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.account.enabled', true);
    config()->set('nvl-auth.routes.management.enabled', true);
    config()->set('nvl-auth.features.principal_management.routes.account.enabled', true);
    config()->set('nvl-auth.features.principal_management.routes.management.enabled', true);
    config()->set('nvl-auth.features.rbac.routes.management.enabled', true);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();
    $actor = $this->user('api.owner@example.test');
    $this->actingAs($actor, 'web');

    $permission = $this->postJson('/api/v1/auth/permissions', [
        'name' => 'articles.publish',
        'displayName' => 'Publish articles',
        'group' => 'articles',
        'system' => true,
    ])->assertCreated()->assertJsonPath('code', 'permission_created');
    $role = $this->postJson('/api/v1/auth/roles', [
        'name' => 'publisher',
        'permissions' => ['articles.publish'],
        'system' => true,
    ])->assertCreated()->assertJsonPath('code', 'role_created');
    $user = $this->postJson('/api/v1/auth/users', [
        'name' => 'API User',
        'email' => 'api.user@example.test',
        'password' => 'SecurePassword123',
        'roles' => ['publisher'],
    ])->assertCreated()->assertJsonPath('code', 'user_created');
    $userId = $user->json('data.id');
    $permissionId = $permission->json('data.id');
    $roleId = $role->json('data.id');

    expect($permission->json('data.id'))->toBeString()
        ->and($permission->json('data.is_system'))->toBeTrue()
        ->and($role->json('data.id'))->toBeString()
        ->and($role->json('data.is_system'))->toBeTrue()
        ->and($userId)->toBeString()
        ->and(Route::has('nvl.auth.account.profile.update'))->toBeTrue()
        ->and(Route::has('nvl.auth.management.users.bulk'))->toBeTrue()
        ->and(Route::has('nvl.auth.management.roles.analytics'))->toBeTrue();

    $this->getJson('/api/v1/auth/users?search=API%20User')
        ->assertOk()
        ->assertJsonPath('data.total', 1);
    $this->getJson('/api/v1/auth/users?perPage=1')
        ->assertOk()
        ->assertJsonPath('data.per_page', 1);
    $this->getJson('/api/v1/auth/roles?perPage=1')
        ->assertOk()
        ->assertJsonPath('data.per_page', 1);
    $this->putJson("/api/v1/auth/permissions/{$permissionId}", [
        'name' => 'articles.publish',
        'displayName' => 'Publish articles',
        'group' => 'articles',
        'system' => true,
    ])->assertOk()
        ->assertJsonPath('code', 'permission_updated');
    $this->putJson("/api/v1/auth/roles/{$roleId}", [
        'name' => 'publisher',
        'permissions' => ['articles.publish'],
        'system' => true,
    ])->assertOk()
        ->assertJsonPath('code', 'role_updated');
    $this->putJson("/api/v1/auth/users/{$userId}", [
        'email' => 'api.user@example.test',
    ])->assertOk()
        ->assertJsonPath('code', 'user_updated');
    $this->patchJson('/api/v1/auth/profile', [
        'name' => 'API Owner Updated',
        'locale' => 'en',
        'timezone' => 'UTC',
        'profile' => ['department' => 'security'],
    ])->assertOk()
        ->assertJsonPath('data.profile.department', 'security');
    $this->patchJson("/api/v1/auth/users/{$userId}/status", ['active' => false])
        ->assertOk()
        ->assertJsonPath('code', 'user_disabled');
    $this->getJson('/api/v1/auth/roles/analytics')
        ->assertOk()
        ->assertJsonPath('data.roles', 1);

    $this->getJson('/api/v1/auth/users?perPage=0')
        ->assertUnprocessable()
        ->assertJsonValidationErrors('perPage');
});

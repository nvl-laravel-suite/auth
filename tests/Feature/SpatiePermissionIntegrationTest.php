<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\AuthSchemaMigration;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Events\RbacAssignmentChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRoles;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Auth\Tests\Fixtures\HostRbacPrincipal;
use Nvl\Auth\Tests\Fixtures\TestPermissionCatalog;
use Nvl\Auth\Tests\Fixtures\TestRoleTemplates;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Spatie\Permission\PermissionRegistrar;

it('rolls back configured RBAC storage when synchronization fails midway', function (string $operation): void {
    config(['database.connections.rbac_custom' => [
        'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true,
    ]]);
    $connection = DB::connection('rbac_custom');
    expect($connection->getDriverName())->toBe('sqlite')->and($connection->getDatabaseName())->toBe(':memory:');
    $authConnection = config('nvl-auth.connection');
    try {
        config(['nvl-auth.connection' => 'rbac_custom']);
        /** @var AuthSchemaMigration $migration */
        $migration = require dirname(__DIR__, 2).'/database/migrations/2026_08_01_000000_nvl_auth_create_nvl_auth_identity_tables.php';
        $migration->up();
    } finally {
        config(['nvl-auth.connection' => $authConnection]);
    }
    $role = new class extends Role
    {
        protected $connection = 'rbac_custom';
    };
    $permission = new class extends Permission
    {
        protected $connection = 'rbac_custom';
    };
    config([
        'nvl-auth.features.rbac.models.role' => $role::class,
        'nvl-auth.features.rbac.models.permission' => $permission::class,
        'permission.models.role' => $role::class,
        'permission.models.permission' => $permission::class,
        'nvl-auth.features.rbac.services.permission_catalogs' => [TestPermissionCatalog::class],
        'nvl-auth.features.rbac.services.role_templates' => [TestRoleTemplates::class],
    ]);
    app(PermissionRegistrar::class)->setRoleClass($role::class)->setPermissionClass($permission::class);
    Event::listen('eloquent.created: '.$permission::class, static function (Permission $model): void {
        if ($model->name === 'users.manage') {
            throw new RuntimeException('Reject second permission.');
        }
    });
    $actor = $this->user();

    expect(fn () => match ($operation) {
        'catalog' => app(AuthPermissions::class)->synchronizeCatalog($actor),
        'templates' => app(AuthRoles::class)->synchronizeTemplates($actor),
        'synchronize' => app(AuthPermissions::class)->synchronize($actor),
        'bootstrap' => app(AuthPermissions::class)->bootstrap(new SystemMutationContext('Install', 'custom-source')),
    })->toThrow(RuntimeException::class, 'Reject second permission.');

    expect($permission::query()->count())->toBe(0)
        ->and($role::query()->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', 'like', 'rbac.%')->count())->toBe(0);
})->with(['catalog', 'templates', 'synchronize', 'bootstrap']);

it('rejects split role and permission storage before synchronization writes', function (string $operation): void {
    config(['database.connections.rbac_custom' => [
        'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true,
    ]]);
    $role = new class extends Role
    {
        protected $connection = 'rbac_custom';
    };
    config([
        'nvl-auth.features.rbac.models.role' => $role::class,
        'nvl-auth.features.rbac.services.permission_catalogs' => [TestPermissionCatalog::class],
        'nvl-auth.features.rbac.services.role_templates' => [TestRoleTemplates::class],
    ]);
    $actor = $this->user();

    expect(fn () => match ($operation) {
        'templates' => app(AuthRoles::class)->synchronizeTemplates($actor),
        'apply' => app(AuthRoles::class)->applyTemplate($actor, ['template' => 'manager']),
        'synchronize' => app(AuthPermissions::class)->synchronize($actor),
        'bootstrap' => app(AuthPermissions::class)->bootstrap(new SystemMutationContext('Install', 'split-source')),
    })->toThrow(AuthException::class, 'same connection');

    expect(Permission::query()->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', 'like', 'rbac.%')->count())->toBe(0);
})->with(['templates', 'apply', 'synchronize', 'bootstrap']);

it('records synchronization success only after the owning transaction commits', function (string $operation, string $action): void {
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $actor = $this->user();
    $synchronize = fn () => match ($operation) {
        'catalog' => app(AuthPermissions::class)->synchronizeCatalog($actor),
        'templates' => app(AuthRoles::class)->synchronizeTemplates($actor),
        'synchronize' => app(AuthPermissions::class)->synchronize($actor),
        'bootstrap' => app(AuthPermissions::class)->bootstrap(new SystemMutationContext('Install', 'commit-source')),
    };
    $connection = DB::connection();
    $connection->beginTransaction();
    try {
        $synchronize();
        expect(AuthAudit::query()->where('action', $action)->count())->toBe(0);
    } finally {
        $connection->rollBack();
    }

    expect(Permission::query()->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', $action)->count())->toBe(0);
    $synchronize();
    expect(AuthAudit::query()->where('action', $action)->count())->toBe(1);
})->with([
    ['catalog', 'rbac.permissions_synchronized'],
    ['templates', 'rbac.roles_synchronized'],
    ['synchronize', 'rbac.synchronized'],
    ['bootstrap', 'rbac.bootstrapped'],
]);

it('synchronizes spatie catalogs and applies invitation role payloads', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $actor = $this->user('actor@example.test');
    $consumer = $this->user('consumer@example.test');
    $consumer->markEmailAsVerified();
    Event::fake([RbacAssignmentChanged::class]);

    expect(app(AuthPermissions::class)->synchronizeCatalog($actor))->toBe(2)
        ->and(app(AuthRoles::class)->synchronizeTemplates($actor))->toBe(1);

    $issued = app(AuthInvitations::class)->create(['recipient' => $consumer->email, 'roles' => ['manager']], $actor);
    app(AuthInvitations::class)->accept($issued['token'], $consumer);

    expect($consumer->fresh()->hasRole('manager'))->toBeTrue()
        ->and($consumer->fresh()->can('users.manage'))->toBeTrue();
    Event::assertDispatched(RbacAssignmentChanged::class, static fn (RbacAssignmentChanged $event): bool => $event->principalId === $consumer->id
        && $event->operation === 'assigned'
        && $event->roles === ['manager']);
});

it('denies actorless synchronization until the host grants system access', function (): void {
    $this->app->singleton(SystemMutationAccess::class, DenySystemMutationAccess::class);

    expect(fn () => app(AuthPermissions::class)->bootstrap(
        new SystemMutationContext('Fresh installation', 'denied-install'),
    ))->toThrow(AuthException::class, 'not authorized');
});

it('synchronizes the complete RBAC contribution through one atomic use case', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);

    $result = app(AuthPermissions::class)->synchronize($this->user('manager@example.test'));

    expect($result)->toBeArray()
        ->and($result)->toBe([
            'permissionsCreated' => 2,
            'rolesSynchronized' => 1,
            'guard' => 'web',
        ]);
});

it('bootstraps RBAC without fabricating a management actor', function (): void {
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $context = new SystemMutationContext('Fresh installation', 'install-2026-08-10');

    $result = app(AuthPermissions::class)->bootstrap($context);

    expect($result['permissionsCreated'])->toBe(2)
        ->and($result['rolesSynchronized'])->toBe(1)
        ->and(AuthAudit::query()->where('action', 'rbac.bootstrapped')->exists())->toBeTrue();
});

it('applies rich template metadata to a caller-selected role name', function (): void {
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    app(AuthPermissions::class)->bootstrap(new SystemMutationContext('Test setup', 'template-setup'));

    $role = app(AuthRoles::class)->applyTemplate(
        $this->user('template.actor@example.test'),
        ['template' => 'manager', 'roleName' => 'regional-manager'],
    );

    expect($role->name)->toBe('regional-manager')
        ->and($role->display_name)->toBe('Manager')
        ->and($role->description)->toBe('Manages host users.')
        ->and($role->parent?->name)->toBe('manager-base')
        ->and($role->priority)->toBe(50)
        ->and($role->metadata)->toBe(['color' => 'blue'])
        ->and($role->hasPermissionTo('users.manage'))->toBeTrue();
});

it('assigns host principal RBAC while principal management is disabled', function (): void {
    config()->set('nvl-auth.features.principal_management.enabled', false);
    config()->set('nvl-auth.features.rbac.models.principal', HostRbacPrincipal::class);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    app(AuthPermissions::class)->bootstrap(new SystemMutationContext('Test setup', 'host-rbac-setup'));
    $principal = (new HostRbacPrincipal)->forceFill([
        'name' => 'Host Principal',
        'email' => 'host-principal@example.test',
        'email_identity_hash' => PrincipalEmailIdentity::key('host-principal@example.test'),
        'password' => 'not-used',
    ]);
    $principal->save();
    Event::fake([RbacAssignmentChanged::class]);

    $updated = app(AuthRoles::class)->syncUserRoles(
        new SystemMutationContext('Candidacy advancement', 'candidate-123'),
        $principal,
        ['roles' => ['manager']],
    );

    expect($updated->hasRole('manager'))->toBeTrue();
    Event::assertDispatched(RbacAssignmentChanged::class, static fn (RbacAssignmentChanged $event): bool => $event->principalId === $principal->id
        && $event->operation === 'roles_synchronized'
        && $event->metadata['system']['correlation_id'] === 'candidate-123');
});

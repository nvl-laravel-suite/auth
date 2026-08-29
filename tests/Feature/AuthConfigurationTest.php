<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Gate;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Models\Permission;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Providers\AuthServiceProvider;
use Nvl\Auth\Services\AuthManagementAbilityCatalog;
use Nvl\Auth\Services\ConfiguredPolicyAuthManagementAccess;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\Tests\Fixtures\EmbeddedPermissionPolicy;
use Nvl\Auth\Tests\Fixtures\EmbeddedRolePolicy;
use Nvl\Auth\Tests\Fixtures\EmbeddedUserPolicy;
use Nvl\Auth\Tests\Fixtures\TestUser;

it('catalogs every package management ability with policy mapping metadata', function (): void {
    $catalog = app(AuthManagementAbilityCatalog::class);
    $expectedAliases = [
        'users.viewAny',
        'users.view',
        'users.create',
        'users.update',
        'users.delete',
        'users.restore',
        'users.manageAccess',
        'invitations.viewAny',
        'invitations.create',
        'invitations.resend',
        'invitations.revoke',
        'clients.viewAny',
        'clients.view',
        'clients.create',
        'clients.update',
        'clients.delete',
        'rbac.view',
        'rbac.manageRoles',
        'rbac.managePermissions',
        'rbac.synchronize',
        'audits.viewAny',
        'audits.view',
    ];
    $catalogAbilities = array_column($catalog->definitions(), 'ability');
    $manifestAbilities = collect(app(FeatureManifest::class)->definitions())
        ->flatMap(static fn ($definition): array => $definition->managementAbilities)
        ->unique()
        ->values()
        ->all();

    sort($catalogAbilities);
    sort($manifestAbilities);

    expect(array_keys($catalog->definitions()))->toBe($expectedAliases)
        ->and($catalogAbilities)->toBe($manifestAbilities)
        ->and($catalog->definitions())->toHaveCount(22)
        ->and($catalog->definition('users.update'))->toMatchArray([
            'ability' => 'nvl-auth.users.update',
            'feature' => AuthFeature::PrincipalManagement,
            'operation' => 'update',
            'subject' => 'target',
            'policy' => 'users',
        ])
        ->and($catalog->definition('rbac.view')['operation'])->toBe('viewRbac')
        ->and($catalog->definition('rbac.manageRoles')['operation'])->toBe('manageRoles')
        ->and($catalog->definition('rbac.managePermissions')['operation'])->toBe('managePermissions')
        ->and($catalog->definition('rbac.synchronize')['operation'])->toBe('synchronizeRbac');
});

it('delegates configured package aliases to host policies and denies unknown or unmapped access', function (): void {
    config()->set('nvl-auth.management', [
        'abilities' => [
            'users.viewAny' => 'viewAny',
            'users.update' => 'manage',
            'rbac.manageRoles' => 'manage',
            'rbac.managePermissions' => 'manage',
        ],
        'policy_models' => [
            'users' => TestUser::class,
            'roles' => Role::class,
            'permissions' => Permission::class,
        ],
    ]);
    Gate::policy(TestUser::class, EmbeddedUserPolicy::class);
    Gate::policy(Role::class, EmbeddedRolePolicy::class);
    Gate::policy(Permission::class, EmbeddedPermissionPolicy::class);
    $access = app(ConfiguredPolicyAuthManagementAccess::class);
    $manager = $this->user('manager@example.test');
    $managed = $this->user('managed@example.test');
    $other = $this->user('other@example.test');

    expect(Gate::has('nvl-auth.users.viewAny'))->toBeFalse()
        ->and($access->allows($manager, 'nvl-auth.users.viewAny'))->toBeTrue()
        ->and($access->allows($manager, 'nvl-auth.users.update', $managed))->toBeTrue()
        ->and($access->allows($manager, 'nvl-auth.users.update', $other))->toBeFalse()
        ->and($access->allows($manager, 'nvl-auth.users.update', new stdClass))->toBeFalse()
        ->and($access->allows($manager, 'nvl-auth.rbac.manageRoles'))->toBeTrue()
        ->and($access->allows($manager, 'nvl-auth.rbac.managePermissions'))->toBeTrue()
        ->and($access->allows($manager, 'nvl-auth.users.delete', $managed))->toBeFalse()
        ->and($access->allows($manager, 'nvl-auth.unknown'))->toBeFalse();

    config()->set('nvl-auth.management.abilities.users.viewAny', 'manage');
    config()->set('nvl-auth.management.policy_models.users', Role::class);

    expect($access->configurationReady('nvl-auth.users.viewAny'))->toBeFalse()
        ->and($access->allows($manager, 'nvl-auth.users.viewAny'))->toBeFalse();

    config()->set('nvl-auth.management.policy_models.users', TestUser::class);

    config()->set('nvl-auth.features.principal_management.enabled', false);

    expect($access->allows($manager, 'nvl-auth.users.update', $managed))->toBeFalse();
});

it('resolves the configured management access implementation through the provider', function (): void {
    config()->set(
        'nvl-auth.services.management_access',
        ConfiguredPolicyAuthManagementAccess::class,
    );
    app()->forgetInstance(AuthManagementAccess::class);
    (new AuthServiceProvider(app()))->register();

    expect(app(AuthManagementAccess::class))
        ->toBeInstanceOf(ConfiguredPolicyAuthManagementAccess::class);
});

it('renders an embedded application overlay and writes only after explicit confirmation', function (): void {
    $path = storage_path('framework/testing/nvl-auth-'.bin2hex(random_bytes(4)).'.php');
    File::delete($path);

    try {
        expect(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--enable' => ['invitations'],
            '--disable' => ['audit'],
            '--path' => $path,
            '--format' => 'json',
        ]))->toBe(0)
            ->and(File::exists($path))->toBeFalse();

        $preview = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
        $contents = $preview['contents'] ?? '';

        expect($contents)
            ->toContain("'http' => 'host'", "'delivery' => 'host'")
            ->toContain("'enabled' => false", TestUser::class)
            ->toContain("'invitations' => ['enabled' => true]")
            ->toContain("'audit' => ['enabled' => false]")
            ->not->toContain("'authentication' => ['enabled'");

        expect(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--path' => $path,
            '--write' => true,
            '--format' => 'json',
        ]))->toBe(0)
            ->and($path)->toBeFile()
            ->and(Artisan::call('nvl:auth:configure', [
                '--preset' => 'embedded-application',
                '--user-model' => TestUser::class,
                '--enable' => ['invitations'],
                '--path' => $path,
                '--format' => 'text',
            ]))->toBe(0)
            ->and(Artisan::output())->toContain('--- config/', '+++ generated/', '@@')
            ->and(Artisan::call('nvl:auth:configure', [
                '--preset' => 'embedded-application',
                '--user-model' => TestUser::class,
                '--path' => $path,
                '--write' => true,
                '--format' => 'json',
            ]))->toBe(2)
            ->and(Artisan::call('nvl:auth:configure', [
                '--preset' => 'embedded-application',
                '--user-model' => TestUser::class,
                '--enable' => ['invitations'],
                '--path' => $path,
                '--write' => true,
                '--force' => true,
                '--format' => 'json',
            ]))->toBe(0);

        $written = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        expect($written['diff'] ?? null)->toContain('--- config/', '+++ generated/', '@@');
    } finally {
        File::delete($path);
    }
});

it('rejects invalid embedded configuration input and unsafe destinations', function (): void {
    expect(Artisan::call('nvl:auth:configure', [
        '--user-model' => TestUser::class,
    ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => 'invalid class',
        ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--enable' => ['unknown'],
        ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--enable' => ['invitations'],
            '--disable' => ['invitations'],
        ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--force' => true,
        ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--path' => sys_get_temp_dir().'/outside-nvl-auth.php',
        ]))->toBe(2)
        ->and(Artisan::call('nvl:auth:configure', [
            '--preset' => 'embedded-application',
            '--user-model' => TestUser::class,
            '--path' => storage_path('framework/testing/nvl-auth.txt'),
        ]))->toBe(2);
});

it('reports Auth integration state and configuration drift without scalar secrets', function (): void {
    config()->set('nvl-auth.features.passkeys.settings.user_handle_key', 'must-never-appear');
    config()->set('nvl-auth.ownership.host_routes', [
        'must-never-appear' => ['must-never-appear'],
    ]);
    config()->set('nvl-auth.ownership.service_only', ['must-never-appear']);

    expect(Artisan::call('nvl:auth:configuration', ['--format' => 'json']))->toBe(0);

    $output = Artisan::output();
    $report = json_decode($output, true, flags: JSON_THROW_ON_ERROR);

    expect($report)->toHaveKeys([
        'features',
        'route_ownership',
        'models',
        'adapters',
        'management',
        'configuration_drift',
    ])->and($report['features']['authentication']['enabled'] ?? null)->toBeTrue()
        ->and($report['models']['user'] ?? null)->toBe(TestUser::class)
        ->and($report['adapters'][PasskeyCeremony::class]['required'] ?? null)->toBeFalse()
        ->and($output)->not->toContain('must-never-appear');
});

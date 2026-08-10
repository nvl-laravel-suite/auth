<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\BootstrapRbacAction;
use Nvl\Auth\Actions\Rbac\SynchronizePermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRbacAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRoleTemplatesAction;
use Nvl\Auth\Actions\Users\SyncUserRolesAction;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Data\Mutations\StoreInvitationData;
use Nvl\Auth\Data\Mutations\SyncUserRolesData;
use Nvl\Auth\Events\RbacAssignmentChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Results\RbacSynchronizationResult;
use Nvl\Auth\Services\DenySystemMutationAccess;
use Nvl\Auth\Tests\Fixtures\HostRbacPrincipal;
use Nvl\Auth\Tests\Fixtures\TestPermissionCatalog;
use Nvl\Auth\Tests\Fixtures\TestRoleTemplates;
use Nvl\Auth\ValueObjects\SystemMutationContext;

it('synchronizes spatie catalogs and applies invitation role payloads', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $actor = $this->user('actor@example.test');
    $consumer = $this->user('consumer@example.test');
    Event::fake([RbacAssignmentChanged::class]);

    expect(app(SynchronizePermissionCatalogAction::class)->execute($actor))->toBe(2)
        ->and(app(SynchronizeRoleTemplatesAction::class)->execute($actor))->toBe(1);

    $issued = app(CreateInvitationAction::class)->execute(new StoreInvitationData(
        recipient: $consumer->email,
        roles: ['manager'],
    ), $actor);
    app(AcceptInvitationAction::class)->execute($issued->token, $consumer);

    expect($consumer->fresh()->hasRole('manager'))->toBeTrue()
        ->and($consumer->fresh()->can('users.manage'))->toBeTrue();
    Event::assertDispatched(RbacAssignmentChanged::class, static fn (RbacAssignmentChanged $event): bool => $event->principalId === $consumer->id
        && $event->operation === 'assigned'
        && $event->roles === ['manager']);
});

it('denies actorless synchronization until the host grants system access', function (): void {
    $this->app->singleton(SystemMutationAccess::class, DenySystemMutationAccess::class);

    expect(fn () => app(BootstrapRbacAction::class)->execute(
        new SystemMutationContext('Fresh installation', 'denied-install'),
    ))->toThrow(AuthException::class, 'not authorized');
});

it('synchronizes the complete RBAC contribution through one atomic use case', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);

    $result = app(SynchronizeRbacAction::class)->execute($this->user('manager@example.test'));

    expect($result)->toBeInstanceOf(RbacSynchronizationResult::class)
        ->and($result->jsonSerialize())->toBe([
            'permissions_created' => 2,
            'roles_synchronized' => 1,
            'guard' => 'web',
        ]);
});

it('bootstraps RBAC without fabricating a management actor', function (): void {
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $context = new SystemMutationContext('Fresh installation', 'install-2026-08-10');

    $result = app(BootstrapRbacAction::class)->execute($context);

    expect($result->permissionsCreated)->toBe(2)
        ->and($result->rolesSynchronized)->toBe(1)
        ->and(AuthAudit::query()->where('action', 'rbac.bootstrapped')->exists())->toBeTrue();
});

it('applies rich template metadata to a caller-selected role name', function (): void {
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    app(BootstrapRbacAction::class)->execute(new SystemMutationContext('Test setup', 'template-setup'));

    $role = app(ApplyRoleTemplateAction::class)->execute(
        $this->user('template.actor@example.test'),
        new ApplyRoleTemplateData('manager', 'regional-manager'),
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
    app(BootstrapRbacAction::class)->execute(new SystemMutationContext('Test setup', 'host-rbac-setup'));
    $principal = HostRbacPrincipal::query()->create([
        'name' => 'Host Principal',
        'email' => 'host-principal@example.test',
        'password' => 'not-used',
    ]);
    Event::fake([RbacAssignmentChanged::class]);

    $updated = app(SyncUserRolesAction::class)->execute(
        new SystemMutationContext('Candidacy advancement', 'candidate-123'),
        $principal,
        new SyncUserRolesData(['manager']),
    );

    expect($updated->hasRole('manager'))->toBeTrue();
    Event::assertDispatched(RbacAssignmentChanged::class, static fn (RbacAssignmentChanged $event): bool => $event->principalId === $principal->id
        && $event->operation === 'roles_synchronized'
        && $event->metadata['system']['correlation_id'] === 'candidate-123');
});

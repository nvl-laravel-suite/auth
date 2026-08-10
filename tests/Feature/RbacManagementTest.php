<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Rbac\ApplyRoleTemplateAction;
use Nvl\Auth\Actions\Rbac\CloneRoleAction;
use Nvl\Auth\Actions\Rbac\CreatePermissionAction;
use Nvl\Auth\Actions\Rbac\CreateRoleAction;
use Nvl\Auth\Actions\Rbac\ListRoleHierarchyAction;
use Nvl\Auth\Actions\Rbac\ListRoleTemplatesAction;
use Nvl\Auth\Actions\Rbac\ShowRbacAnalyticsAction;
use Nvl\Auth\Data\Mutations\ApplyRoleTemplateData;
use Nvl\Auth\Data\Mutations\StorePermissionData;
use Nvl\Auth\Data\Mutations\StoreRoleData;

it('owns role and permission CRUD foundations, cloning, hierarchy, templates, and analytics', function (): void {
    $actor = $this->user('rbac.owner@example.test');
    app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('catalog.read', group: 'catalog'));
    app(CreatePermissionAction::class)->execute($actor, new StorePermissionData('catalog.write', group: 'catalog'));
    $parent = app(CreateRoleAction::class)->execute($actor, new StoreRoleData(
        name: 'catalog-manager',
        priority: 100,
        permissions: ['catalog.read', 'catalog.write'],
    ));
    $child = app(CreateRoleAction::class)->execute($actor, new StoreRoleData(
        name: 'catalog-reader',
        parentId: $parent->id,
        priority: 50,
        permissions: ['catalog.read'],
    ));
    $clone = app(CloneRoleAction::class)->execute($actor, $child, 'catalog-observer');
    $actor->assignRole($parent);
    $templates = app(ListRoleTemplatesAction::class)->execute($actor);
    $template = app(ApplyRoleTemplateAction::class)->execute($actor, new ApplyRoleTemplateData('auth-auditor'));
    $hierarchy = app(ListRoleHierarchyAction::class)->execute($actor);
    $parentNode = collect($hierarchy)->firstWhere('id', $parent->id);
    $childNode = collect($parentNode['children'] ?? [])->firstWhere('id', $child->id);
    $analytics = app(ShowRbacAnalyticsAction::class)->execute($actor);

    expect($clone->hasPermissionTo('catalog.read'))->toBeTrue()
        ->and($clone->is_system)->toBeFalse()
        ->and(collect($templates)->pluck('key')->all())->toBe(['auth-auditor', 'auth-user-manager', 'super-admin'])
        ->and($template->is_system)->toBeTrue()
        ->and($template->hasPermissionTo('nvl-auth.audits.view'))->toBeTrue()
        ->and($parentNode)->toBeArray()
        ->and($childNode)->toBeArray()
        ->and($analytics->roles)->toBe(4)
        ->and($analytics->permissions)->toBeGreaterThanOrEqual(4)
        ->and($analytics->roleAssignments)->toBe(1);
});

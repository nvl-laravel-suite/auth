<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Invitations\AcceptInvitationAction;
use Nvl\Auth\Actions\Invitations\CreateInvitationAction;
use Nvl\Auth\Actions\Rbac\SynchronizePermissionCatalogAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRbacAction;
use Nvl\Auth\Actions\Rbac\SynchronizeRoleTemplatesAction;
use Nvl\Auth\Tests\Fixtures\TestPermissionCatalog;
use Nvl\Auth\Tests\Fixtures\TestRoleTemplates;
use Nvl\Auth\ValueObjects\CreateInvitationData;

it('synchronizes spatie catalogs and applies invitation role payloads', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.invitations.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);
    $actor = $this->user('actor@example.test');
    $consumer = $this->user('consumer@example.test');

    expect(app(SynchronizePermissionCatalogAction::class)->execute($actor))->toBe(2)
        ->and(app(SynchronizeRoleTemplatesAction::class)->execute($actor))->toBe(1);

    $issued = app(CreateInvitationAction::class)->execute(new CreateInvitationData(
        recipient: $consumer->email,
        roles: ['manager'],
    ), $actor);
    app(AcceptInvitationAction::class)->execute($issued->token, $consumer);

    expect($consumer->fresh()->hasRole('manager'))->toBeTrue()
        ->and($consumer->fresh()->can('users.manage'))->toBeTrue();
});

it('synchronizes the complete RBAC contribution through one atomic use case', function (): void {
    config()->set('nvl-auth.features.rbac.enabled', true);
    config()->set('nvl-auth.features.rbac.services.permission_catalogs', [TestPermissionCatalog::class]);
    config()->set('nvl-auth.features.rbac.services.role_templates', [TestRoleTemplates::class]);

    $result = app(SynchronizeRbacAction::class)->execute($this->user('manager@example.test'));

    expect($result)->toBe([
        'permissions_created' => 2,
        'roles_synchronized' => 1,
    ]);
});

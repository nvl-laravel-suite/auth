<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Challenges\ConsumeMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAction;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthResourceRegistrar;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipException;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;

uses(OwnerScopeTestCase::class);

it('keeps central user administration unavailable inside an ordinary owner scope', function (): void {
    expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipViolation::class);
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function (): void {
        expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipViolation::class);
    });
});

it('keeps global identity operations available without selecting or joining an owner', function (): void {
    $user = User::factory()->create();
    $session = Mockery::mock(BrowserSession::class);
    $session->shouldReceive('regenerateIdentifier')->once();
    $this->app->instance(BrowserSession::class, $session);
    $principal = app(LoginAction::class)->execute(new LoginData($user->email, 'password'));
    expect($principal->getAuthIdentifier())->toBe($user->id);
    expect(Company::query()->count())->toBe(2)
        ->and((new OwnerMembership)->getConnection()->table('nvl_auth_owner_memberships')->count())->toBe(0);
});

it('rejects queries after disabling native ownership or selecting legacy tenancy on adopted storage', function (): void {
    config(['nvl-ownership.enabled' => false, 'nvl-auth.ownership.scoped' => false]);
    expect(fn () => Role::query()->get())->toThrow(OwnershipException::class);
    config(['nvl-tenancy.enabled' => true]);
    expect(fn () => Role::query()->get())->toThrow(OwnershipException::class);
});

it('rechecks the canonical owners availability on every entry', function (): void {
    $company = Company::query()->findOrFail(7);
    $company->forceFill(['active' => false])->save();
    expect(fn () => app(OwnershipRunner::class)->run($company, Actor::query()->findOrFail(1), static fn () => true))->toThrow(OwnershipViolation::class);
});

it('issues and consumes global credential challenges without owner admission', function (): void {
    config(['nvl-auth.features.magic_links.enabled' => true]);
    $issued = app(RequestMagicLinkAction::class)->execute(new RequestMagicLinkData('login@example.test'));
    expect($issued->challenge->isUsable())->toBeTrue();
    $data = new ConsumeMagicLinkData(token: $issued->secret, recipient: 'login@example.test');
    $consumed = app(ConsumeMagicLinkAction::class)->execute($data);
    expect($consumed->getKey())->toBe($issued->challenge->getKey())
        ->and(fn () => app(ConsumeMagicLinkAction::class)->execute($data))->toThrow(AuthException::class);
});

it('cannot declassify adopted Auth administration by changing its runtime flag', function (): void {
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function (): void {
        config(['nvl-auth.ownership.scoped' => false]);
        expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipException::class);
    });
});

it('detects adopted Auth storage when booted with unscoped declarations', function (): void {
    config(['nvl-auth.ownership.scoped' => false, 'nvl-ownership.enabled' => false]);
    $resources = new OwnershipResourceRegistry;
    app(AuthResourceRegistrar::class)->register($resources);
    $this->app->instance(OwnershipResourceRegistry::class, $resources);
    expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipException::class);
});

it('cannot declassify adopted membership admission by disabling the membership feature', function (): void {
    config(['nvl-auth.features.memberships.enabled' => false]);
    expect(fn () => app(FeatureGate::class)->assertAllowed(AuthFeature::Authentication, FeatureOperation::Read))
        ->toThrow(OwnershipException::class);
});

it('rechecks native RBAC pivot constraints before entering another owner scope', function (): void {
    $connection = (new Role)->getConnection();
    if ($connection->getDriverName() !== 'sqlite') {
        $this->markTestSkipped('SQLite trigger-removal path; native writes and race tests cover PostgreSQL.');
    }
    $runner = app(OwnershipRunner::class);
    $runner->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), static fn () => true);
    foreach ($connection->table('sqlite_master')->where('type', 'trigger')->where('tbl_name', 'nvl_auth_model_has_roles')->get() as $trigger) {
        $connection->statement('DROP TRIGGER '.$connection->getQueryGrammar()->wrap($trigger->name));
    }
    expect(fn () => $runner->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), static fn () => true))->toThrow(OwnershipException::class);
});

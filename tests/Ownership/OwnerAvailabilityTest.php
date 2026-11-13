<?php

declare(strict_types=1);

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\Role;
use Nvl\Auth\Models\User;
use Nvl\Auth\Ownership\AuthResourceRegistrar;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\Tests\Fixtures\OptsIntoAdoptedSchemaReuse;
use Nvl\Support\Ownership\Exceptions\OwnershipException;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;

uses(OwnerScopeTestCase::class, OptsIntoAdoptedSchemaReuse::class);

it('keeps global identity operations available without selecting or joining an owner', function (): void {
    expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipViolation::class);
    $user = User::factory()->create();
    $session = app('session')->driver();
    $session->start();
    $previousSessionId = $session->getId();
    $principal = app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'password'], [], auth()->guard('web'), app('session')->driver());
    expect($principal->getAuthIdentifier())->toBe($user->id)->and($session->getId())->not->toBe($previousSessionId);
    expect(Company::query()->count())->toBe(2)
        ->and((new OwnerMembership)->getConnection()->table('nvl_auth_owner_memberships')->count())->toBe(0);
});

it('rejects queries after disabling native ownership or selecting legacy tenancy on adopted storage', function (): void {
    $this->withFixtureConfiguration(['nvl-ownership.enabled' => false, 'nvl-auth.ownership.scoped' => false], function (): void {
        expect(fn () => Role::query()->get())->toThrow(OwnershipException::class);
        $this->withFixtureConfiguration(['nvl-tenancy.enabled' => true], function (): void {
            expect(fn () => Role::query()->get())->toThrow(OwnershipException::class);
        });
    });
});

it('rechecks the canonical owners availability on every entry', function (): void {
    $company = Company::query()->findOrFail(7);
    $company->forceFill(['active' => false])->save();
    expect(fn () => app(OwnershipRunner::class)->run($company, Actor::query()->findOrFail(1), static fn () => true))->toThrow(OwnershipViolation::class);
});

it('issues and consumes global credential challenges without owner admission', function (): void {
    $this->withFixtureConfiguration(['nvl-auth.features.magic_links.enabled' => true], function (): void {
        $issued = app(AuthChallenges::class)->requestMagicLink(['recipient' => 'login@example.test']);
        expect($issued['challenge']->isUsable())->toBeTrue();
        $data = ['token' => $issued['secret'], 'recipient' => 'login@example.test'];
        $consumed = app(AuthChallenges::class)->consumeMagicLink($data);
        expect($consumed->getKey())->toBe($issued['challenge']->getKey())
            ->and(fn () => app(AuthChallenges::class)->consumeMagicLink($data))->toThrow(AuthException::class);
    });
});

it('keeps adopted Auth administration fenced across runtime and boot configuration changes', function (): void {
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function (): void {
        $this->withFixtureConfiguration(['nvl-auth.ownership.scoped' => false], function (): void {
            expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipException::class);
        });
    });
    $original = app(OwnershipResourceRegistry::class);
    $this->withFixtureConfiguration(['nvl-auth.ownership.scoped' => false, 'nvl-ownership.enabled' => false], function () use ($original): void {
        $resources = new OwnershipResourceRegistry;
        app(AuthResourceRegistrar::class)->register($resources);
        $this->app->instance(OwnershipResourceRegistry::class, $resources);
        try {
            expect(fn () => app(AuthOperationBoundary::class)->requirePlatformAdministration())->toThrow(OwnershipException::class);
        } finally {
            $this->app->instance(OwnershipResourceRegistry::class, $original);
        }
    });
});

it('cannot declassify adopted membership admission by disabling the membership feature', function (): void {
    $this->withFixtureConfiguration(['nvl-auth.features.memberships.enabled' => false], function (): void {
        expect(fn () => app(FeatureGate::class)->assertAllowed(AuthFeature::Authentication, FeatureOperation::Read))
            ->toThrow(OwnershipException::class);
    });
});

it('rechecks native RBAC pivot constraints before entering another owner scope', function (): void {
    $connection = (new Role)->getConnection();
    $runner = app(OwnershipRunner::class);
    $runner->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), static fn () => true);
    foreach ($connection->table('sqlite_master')->where('type', 'trigger')->where('tbl_name', 'nvl_auth_model_has_roles')->get() as $trigger) {
        $connection->statement('DROP TRIGGER '.$connection->getQueryGrammar()->wrap($trigger->name));
    }
    expect(fn () => $runner->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), static fn () => true))->toThrow(OwnershipException::class);
})->group('fresh-adoption', 'sqlite-trigger-removal');

<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Ownership\AuthAdoptionAdapter;
use Nvl\Auth\Services\AuthOwnershipState;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Tests\GlobalAuthOwnerScopeTestCase;
use Nvl\Ownership\Services\OwnershipAdoptionScope;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Support\Ownership\Exceptions\OwnershipException;
use Spatie\Permission\PermissionRegistrar;

uses(GlobalAuthOwnerScopeTestCase::class);

it('leaves host RBAC state intact when Auth did not opt into ownership', function (): void {
    $this->allowOwners();
    $registrar = app(PermissionRegistrar::class);
    $registrar->setPermissionsTeamId('host-owned-rbac-scope');
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($registrar): void {
        expect($registrar->getPermissionsTeamId())->toBe('host-owned-rbac-scope');
    });
    expect($registrar->getPermissionsTeamId())->toBe('host-owned-rbac-scope');
});

it('does not cache a negative native-storage result across a changed actual Auth source', function (): void {
    Schema::create('nvl_auth_roles', static function (Blueprint $table): void {
        $table->uuid('id')->primary();
    });
    $state = app(AuthOwnershipState::class);
    expect($state->native())->toBeFalse();
    Schema::table('nvl_auth_roles', static fn (Blueprint $table) => $table->string('owner_scope_key')->nullable());
    expect(fn () => $state->native())->toThrow(OwnershipException::class);
});

it('denies ordinary Auth operations inside a coordinated adoption callback', function (): void {
    expect(fn () => app(OwnershipAdoptionScope::class)->during('probe', AuthAdoptionAdapter::class, 'metadata', fn () => app(FeatureGate::class)->assertAllowed(AuthFeature::Authentication, FeatureOperation::Read)))
        ->toThrow(OwnershipException::class);
});

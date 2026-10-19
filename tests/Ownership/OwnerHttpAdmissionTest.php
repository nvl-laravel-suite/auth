<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Http\Middleware\EnsureAuthOwnerAccess;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\OwnerMemberships;
use Nvl\Auth\Tests\OwnerScopeTestCase;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Ownership\Services\OwnershipRunner;
use Nvl\Ownership\Tests\Fixtures\Actor;
use Nvl\Ownership\Tests\Fixtures\Company;

uses(OwnerScopeTestCase::class);

it('requires authenticated fresh owner admission on HTTP without inferring ownership from input', function (): void {
    Route::get('/native-owner-probe', static fn () => response()->json(['admitted' => true]))->middleware(EnsureAuthOwnerAccess::class);
    $user = User::factory()->create();
    $this->actingAs($user)->getJson('/native-owner-probe?owner=7')->assertNotFound();
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(7), Actor::query()->findOrFail(1), function () use ($user): void {
        $this->getJson('/native-owner-probe')->assertNotFound();
        app(OwnerMemberships::class)->provision(new SystemMutationContext('bootstrap', 'http'), SubjectReference::fromAuthenticatable($user));
        $this->getJson('/native-owner-probe')->assertOk()->assertJson(['admitted' => true]);
    });
    app(OwnershipRunner::class)->run(Company::query()->findOrFail(8), Actor::query()->findOrFail(1), function (): void {
        $this->getJson('/native-owner-probe?owner=7')->assertNotFound();
    });
});

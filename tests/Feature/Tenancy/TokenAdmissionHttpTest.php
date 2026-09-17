<?php

declare(strict_types=1);

use Nvl\Auth\Actions\ApiTokens\CreateApiTokenAction;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Http\Middleware\EnsureAuthTenantAccess;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Services\AuthTenantAdmission;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Http\Middleware\RequireTenantMembership;

it('admits sessions only where fresh membership exists', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));

    $middleware = app('router')->getRoutes()->getByName('nvl.auth.account.api_tokens.index')?->gatherMiddleware() ?? [];
    expect(route('nvl.auth.account.api_tokens.index'))->not->toBeEmpty()
        ->and($middleware)->toContain(EnsureAuthTenantAccess::class)
        ->and(array_search(EnsureAuthTenantAccess::class, $middleware, true))
        ->toBeLessThan(array_search(RequireTenantMembership::class, $middleware, true));

    $this->actingAs($user)
        ->withHeader('X-Test-Tenant', $scenario->a()->value)
        ->getJson(route('nvl.auth.account.api_tokens.index'))
        ->assertOk();

    $this->actingAs($user)
        ->withHeader('X-Test-Tenant', $scenario->b()->value)
        ->getJson(route('nvl.auth.account.api_tokens.index'))
        ->assertNotFound();
});

it('rejects a persisted tenant token in another tenant despite membership there', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $scenario->member($scenario->a(), $reference);
    $scenario->member($scenario->b(), $reference);
    $issued = $scenario->run($scenario->a(), fn () => app(CreateApiTokenAction::class)->execute(
        $user,
        new ApiTokenData('automation', ['profile:read']),
    ));
    $persisted = PersonalAccessToken::query()->findOrFail($issued->token->id);
    $user->withAccessToken($persisted);

    app(AuthTenantAdmission::class)->assertAllowed($user, $scenario->a());

    expect(fn () => app(AuthTenantAdmission::class)->assertAllowed($user, $scenario->b()))
        ->toThrow(AuthException::class);
});

it('rechecks membership and principal eligibility after token issuance', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user();
    $membership = $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($user));
    $issued = $scenario->run($scenario->a(), fn () => app(CreateApiTokenAction::class)->execute(
        $user,
        new ApiTokenData('automation', ['profile:read']),
    ));
    $user->withAccessToken(PersonalAccessToken::query()->findOrFail($issued->token->id));
    $membership->forceFill(['status' => MembershipStatus::Revoked])->save();

    expect(fn () => app(AuthTenantAdmission::class)->assertAllowed($user, $scenario->a()))
        ->toThrow(AuthException::class);

    $membership->forceFill(['status' => MembershipStatus::Active])->save();
    $user->forceFill(['is_active' => false])->save();

    expect(fn () => app(AuthTenantAdmission::class)->assertAllowed($user, $scenario->a()))
        ->toThrow(AuthException::class);
});

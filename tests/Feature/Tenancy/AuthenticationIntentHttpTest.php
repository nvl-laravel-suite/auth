<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Adapters\Laravel\LaravelBrowserSession;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

it('preserves a server flow binding across session identifier regeneration', function (): void {
    $request = Request::create('/');
    $request->setLaravelSession(app('session')->driver());
    $session = new LaravelBrowserSession($request);
    $binding = $session->authenticationFlowBinding('social:github');

    $session->regenerateIdentifier();

    expect($session->authenticationFlowBinding('social:github'))->toBe($binding)
        ->and($binding)->not->toBeEmpty();
});

it('keeps global login successful when requested tenant membership is denied', function (): void {
    $scenario = new AuthTenancyScenario;
    $user = $this->user('login@example.test');
    $issued = app(TenantAuthenticationIntents::class)->issue(
        $scenario->a(),
        TenantAuthenticationPurpose::Login,
        'login-flow',
    );

    $authenticated = app(LoginAction::class)->execute(
        new LoginData('login@example.test', 'correct-password'),
        new AuthenticationRequestContext(
            tenantIntentNonce: $issued->nonce,
            tenantSessionBinding: 'login-flow',
            tenantPurpose: TenantAuthenticationPurpose::Login,
            requestedTenant: $scenario->a(),
        ),
    );

    expect($authenticated->getAuthIdentifier())->toBe($user->getAuthIdentifier())
        ->and(TenantMembership::query()->where('subject_id', $user->getAuthIdentifier())->exists())->toBeFalse();
});

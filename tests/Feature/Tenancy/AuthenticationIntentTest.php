<?php

declare(strict_types=1);

use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\Tests\Fixtures\AuthTenancyScenario;

it('binds and consumes one tenant intent once', function (): void {
    $scenario = new AuthTenancyScenario;
    $intents = app(TenantAuthenticationIntents::class);
    $issued = $intents->issue(
        $scenario->a(),
        TenantAuthenticationPurpose::SocialLogin,
        'server-flow-secret',
        provider: 'github',
    );

    expect(fn () => $intents->consume(
        $issued->nonce,
        TenantAuthenticationPurpose::SocialLogin,
        'wrong-flow',
        provider: 'github',
    ))->toThrow(AuthException::class)
        ->and(TenantAuthenticationIntent::query()->findOrFail($issued->id)->consumed_at)->toBeNull()
        ->and($intents->consume(
            $issued->nonce,
            TenantAuthenticationPurpose::SocialLogin,
            'server-flow-secret',
            provider: 'github',
        )->value)->toBe($scenario->a()->value)
        ->and(fn () => $intents->consume(
            $issued->nonce,
            TenantAuthenticationPurpose::SocialLogin,
            'server-flow-secret',
            provider: 'github',
        ))->toThrow(AuthException::class);
});

it('keeps same-browser concurrent flows independent', function (): void {
    $scenario = new AuthTenancyScenario;
    $intents = app(TenantAuthenticationIntents::class);
    $a = $intents->issue($scenario->a(), TenantAuthenticationPurpose::Login, 'flow-a', returnPath: '/a');
    $b = $intents->issue($scenario->b(), TenantAuthenticationPurpose::Login, 'flow-b', returnPath: '/b');

    expect($intents->consume($b->nonce, TenantAuthenticationPurpose::Login, 'flow-b')->value)
        ->toBe($scenario->b()->value)
        ->and($intents->consume($a->nonce, TenantAuthenticationPurpose::Login, 'flow-a')->value)
        ->toBe($scenario->a()->value);
});

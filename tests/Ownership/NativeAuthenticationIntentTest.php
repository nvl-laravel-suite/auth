<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\OwnerAuthenticationIntents;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;

it('binds and consumes one tenant intent once', function (): void {
    $scenario = new AuthOwnerScenario;
    $intents = app(OwnerAuthenticationIntents::class);
    $issued = $intents->issue(
        $scenario->a(),
        OwnerAuthenticationPurpose::SocialLogin,
        'server-flow-secret',
        provider: 'github',
    );

    expect(fn () => $intents->consume(
        $issued['nonce'],
        OwnerAuthenticationPurpose::SocialLogin,
        'wrong-flow',
        $scenario->a(),
        provider: 'github',
    ))->toThrow(AuthException::class)
        ->and(DB::table('nvl_auth_owner_authentication_intents')->where('id', $issued['id'])->value('consumed_at'))->toBeNull()
        ->and($intents->consume(
            $issued['nonce'],
            OwnerAuthenticationPurpose::SocialLogin,
            'server-flow-secret',
            $scenario->a(),
            provider: 'github',
        )->scopeKey())->toBe($scenario->a()->scopeKey())
        ->and(fn () => $intents->consume(
            $issued['nonce'],
            OwnerAuthenticationPurpose::SocialLogin,
            'server-flow-secret',
            $scenario->a(),
            provider: 'github',
        ))->toThrow(AuthException::class);
});

it('keeps same-browser concurrent flows independent', function (): void {
    $scenario = new AuthOwnerScenario;
    $intents = app(OwnerAuthenticationIntents::class);
    $a = $intents->issue($scenario->a(), OwnerAuthenticationPurpose::Login, 'flow-a', returnPath: '/a');
    $b = $intents->issue($scenario->b(), OwnerAuthenticationPurpose::Login, 'flow-b', returnPath: '/b');

    expect($intents->consume($b['nonce'], OwnerAuthenticationPurpose::Login, 'flow-b', $scenario->b())->scopeKey())
        ->toBe($scenario->b()->scopeKey())
        ->and($intents->consume($a['nonce'], OwnerAuthenticationPurpose::Login, 'flow-a', $scenario->a())->scopeKey())
        ->toBe($scenario->a()->scopeKey());
});

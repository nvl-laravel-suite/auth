<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Challenges\ConsumeMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAuthenticationAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAction;
use Nvl\Auth\Actions\Challenges\VerifySecurityCodeAction;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;

it('issues hashed magic links and consumes them once', function (): void {
    config()->set('nvl-auth.features.magic_links.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    $issued = app(RequestMagicLinkAction::class)->execute('user@example.test');

    expect($issued->challenge->getRawOriginal('secret_hash'))->not->toBe($issued->secret);

    $consumed = app(ConsumeMagicLinkAction::class)->execute('user@example.test', $issued->secret);

    expect($consumed->consumed_at)->not->toBeNull()
        ->and(fn () => app(ConsumeMagicLinkAction::class)->execute('user@example.test', $issued->secret))
        ->toThrow(AuthException::class);
    Event::assertDispatched(AuthDeliveryRequested::class);
});

it('binds public login links to resolved subjects and stays neutral for unknown identifiers', function (): void {
    config()->set('nvl-auth.features.magic_links.enabled', true);
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();

    $issued = app(RequestMagicLinkAuthenticationAction::class)->execute($user->email);

    expect($issued)->not->toBeNull()
        ->and($issued?->challenge->subject_id)->toBe((string) $user->getKey())
        ->and(app(RequestMagicLinkAuthenticationAction::class)->execute('unknown@example.test'))->toBeNull();

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
});

it('scopes numeric codes to their recipient and purpose', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    $issued = app(RequestSecurityCodeAction::class)->execute('user@example.test', 'login');

    expect(fn () => app(VerifySecurityCodeAction::class)->execute('other@example.test', 'login', $issued->secret))
        ->toThrow(AuthException::class);

    expect(app(VerifySecurityCodeAction::class)->execute('user@example.test', 'login', $issued->secret)->consumed_at)
        ->not->toBeNull();
});

it('commits failed challenge attempts instead of rolling them back with the response', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    $issued = app(RequestSecurityCodeAction::class)->execute('user@example.test', 'login');
    $wrongCode = $issued->secret === '000000' ? '111111' : '000000';

    expect(fn () => app(VerifySecurityCodeAction::class)->execute('user@example.test', 'login', $wrongCode))
        ->toThrow(AuthException::class);

    expect(Challenge::query()->sole()->attempts)->toBe(1);
});

it('keeps one active challenge and caps committed attempts', function (): void {
    config()->set('nvl-auth.features.security_codes.enabled', true);
    config()->set('nvl-auth.features.security_codes.settings.max_attempts', 2);
    $first = app(RequestSecurityCodeAction::class)->execute('user@example.test', 'login');
    $second = app(RequestSecurityCodeAction::class)->execute('user@example.test', 'login');
    $wrongCode = $second->secret === '000000' ? '111111' : '000000';

    expect($first->challenge->refresh()->revoked_at)->not->toBeNull()
        ->and($first->challenge->active_key)->toBeNull()
        ->and($second->challenge->active_key)->not->toBeNull();

    foreach ([1, 2, 3] as $attempt) {
        expect(fn () => app(VerifySecurityCodeAction::class)->execute('user@example.test', 'login', $wrongCode))
            ->toThrow(AuthException::class);
    }

    expect($second->challenge->refresh()->attempts)->toBe(2)
        ->and($second->challenge->active_key)->toBeNull()
        ->and(fn () => app(VerifySecurityCodeAction::class)->execute('user@example.test', 'login', $second->secret))
        ->toThrow(AuthException::class);
});

<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;

it('publishes explicit native credential and session contracts', function (): void {
    foreach ([
        [Authentication::class, 'verifyCredentials', ['array'], Authenticatable::class],
        [Authentication::class, 'login', ['array', 'array', StatefulGuard::class, Session::class], Authenticatable::class],
        [AuthenticationSessions::class, 'establish', [Authenticatable::class, StatefulGuard::class, Session::class, 'bool'], 'void'],
    ] as [$class, $method, $parameters, $return]) {
        $reflection = new ReflectionMethod($class, $method);
        expect(array_map(static fn (ReflectionParameter $parameter): string => (string) $parameter->getType(), $reflection->getParameters()))->toBe($parameters)
            ->and((string) $reflection->getReturnType())->toBe($return);
    }
});

it('consumes native challenges with committed attempts and exact protocol bindings', function (): void {
    config(['nvl-auth.features.security_codes.enabled' => true, 'nvl-auth.features.magic_links.enabled' => true]);
    $challenges = app(AuthChallenges::class);
    $issued = $challenges->issue(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', CarbonImmutable::now()->addMinutes(5), numeric: true, maxAttempts: 2);
    $secret = $issued['secret'];
    expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', $secret === '000000' ? '111111' : '000000'))->toThrow(AuthException::class);
    expect($issued['challenge']->refresh()->attempts)->toBe(1);
    expect(fn () => $challenges->consumeById(AuthFeature::MagicLinks, AuthMessageType::MagicLink, $issued['challenge']->identifier(), 'login', $secret))->toThrow(AuthException::class);
    expect($issued['challenge']->refresh()->consumed_at)->toBeNull();
    $consumed = $challenges->consumeById(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, $issued['challenge']->identifier(), 'login', $secret);
    expect($consumed->consumed_at)->not->toBeNull()
        ->and($consumed->toArray())->not->toHaveKeys(['secret_hash', 'secondary_secret_hash'])
        ->and(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', $secret))->toThrow(AuthException::class);
});

it('keeps challenge SQL expiry and failed attempts on UTC instants under host timezones', function (string $timezone): void {
    $original = date_default_timezone_get();
    date_default_timezone_set($timezone);
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25T12:00:00Z'));
    try {
        config(['app.timezone' => $timezone, 'nvl-auth.features.security_codes.enabled' => true]);
        $challenges = app(AuthChallenges::class);
        $issued = $challenges->issue(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', CarbonImmutable::now($timezone)->addMinute(), numeric: true);
        expect($issued['challenge']->getRawOriginal('expires_at'))->toBe('2026-10-25 12:01:00');
        expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', 'wrong'))->toThrow(AuthException::class);
        expect($issued['challenge']->refresh()->attempts)->toBe(1);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25T12:02:00Z'));
        expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', $issued['secret']))->toThrow(AuthException::class);
        expect($issued['challenge']->refresh()->active_key)->toBeNull()
            ->and($issued['challenge']->consumed_at)->toBeNull()
            ->and($issued['challenge']->attempts)->toBe(1);
    } finally {
        CarbonImmutable::setTestNow();
        date_default_timezone_set($original);
    }
})->with(['Europe/Sofia', 'America/New_York']);

it('verifies credentials without logging in and completes login with the supplied guard and session', function (): void {
    $user = $this->user('native-login@example.test');
    $guard = auth()->guard('web');
    $session = app('session.store');
    $session->start();
    $before = $session->getId();
    $authentication = app(Authentication::class);
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    expect($authentication->verifyCredentials($credentials)->getAuthIdentifier())->toBe($user->id)
        ->and($guard->check())->toBeFalse();
    $authenticated = $authentication->login($credentials, [], $guard, $session);
    expect($authenticated->getAuthIdentifier())->toBe($user->id)
        ->and($guard->id())->toBe($user->id)
        ->and($session->getId())->not->toBe($before);
});

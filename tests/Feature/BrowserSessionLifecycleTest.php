<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Nvl\Auth\Adapters\Laravel\LaravelSessionAdmission;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware\ApplyAuthSecurityHeaders;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware\AuthenticateAuthGuard;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Middleware\RenderAuthExceptions;

it('creates a secret bound registry entry only after native login and throttles admission heartbeats', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $user = $this->user();
    $session = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session);
    $entry = BrowserSession::query()->sole();
    $binding = $session->get(AuthBrowserSessions::bindingKey('web'));
    expect($entry->absolute_expires_at->diffInSeconds($entry->authenticated_at, true))->toBe(43200.0)
        ->and($entry->toArray())->not->toHaveKeys(['binding_hash', 'assurance']);
    $service = app(AuthBrowserSessions::class);
    $seen = $entry->last_seen_at;
    $service->admit($user, 'web', $binding);
    expect($entry->refresh()->last_seen_at->equalTo($seen))->toBeTrue();
    $this->travel(61)->seconds();
    $service->admit($user, 'web', $binding);
    expect($entry->refresh()->last_seen_at->greaterThan($seen))->toBeTrue();
    expect(fn () => $service->admit($user, 'other', $binding))->toThrow(AuthException::class);
    $entry->update(['revoked_at' => now()]);
    expect(fn () => $service->admit($user, 'web', $binding))->toThrow(AuthException::class);
});

it('never enrolls arbitrary guard authentication and rejects cookie driver managed sessions', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $user = $this->user();
    auth()->guard('web')->login($user);
    expect(fn () => app(LaravelSessionAdmission::class)->admit(auth()->guard('web'), app('session.store'), 'web'))->toThrow(AuthException::class);
    expect(auth()->guard('web')->check())->toBeFalse()->and(BrowserSession::query()->count())->toBe(0);
    config(['session.driver' => 'cookie']);
    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store')))->toThrow(AuthException::class);
});

it('denies an untracked host request before its controller executes', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $reached = false;
    Route::middleware(['web', RenderAuthExceptions::class, ApplyAuthSecurityHeaders::class, AuthenticateAuthGuard::class])->get('/managed-admission-probe', function () use (&$reached) {
        $reached = true;

        return response()->json(['ok' => true]);
    });
    $this->actingAs($this->user())->getJson('/managed-admission-probe')->assertUnauthorized();
    expect($reached)->toBeFalse();
});

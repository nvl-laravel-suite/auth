<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthRememberCredentials;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use PragmaRX\Google2FA\Google2FA;

it('rotates an encrypted per family recaller with its original absolute deadline', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'auth.guards.web.driver' => 'nvl-managed-session', 'session.secure' => true, 'session.http_only' => true]);
    auth()->forgetGuards();
    $user = $this->user();
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], ['remember' => true], $guard, $store);
    $cookie = collect(app('cookie')->getQueuedCookies())->first(fn ($cookie) => $cookie->getName() === $guard->getRecallerName());
    expect($cookie)->not->toBeNull()->and($cookie->isSecure())->toBeTrue()->and($cookie->isHttpOnly())->toBeTrue();
    [$selector, $secret] = explode('.', app('encrypter')->decryptString($cookie->getValue()), 2);
    $original = RememberCredential::query()->sole();
    $expiry = $original->absolute_expires_at;
    expect($original->toArray())->not->toHaveKeys(['secret_hash', 'selector']);
    $this->travel(1)->days();
    $next = new Store('managed-next', new ArraySessionHandler(120));
    $next->start();
    app()->instance('session.store', $next);
    app()->instance('request', Request::create('/private', 'GET', [], [$cookie->getName() => $cookie->getValue()]));
    auth()->forgetGuards();
    expect(auth()->guard('web')->user()->getAuthIdentifier())->toBe($user->getAuthIdentifier());
    $replacement = RememberCredential::query()->whereKeyNot($original->identifier())->sole();
    expect($replacement->absolute_expires_at->equalTo($expiry))->toBeTrue()->and($original->refresh()->consumed_at)->not->toBeNull()->and(BrowserSession::query()->count())->toBe(2);
    expect(fn () => app(AuthRememberCredentials::class)->resume($selector, $secret, 'web', new AuthenticationRequestContext(guardName: 'web', sessionBinding: $next->getId())))->toThrow(AuthException::class);
    $binding = $next->get(AuthBrowserSessions::bindingKey('web'));
    $sessions = app(AuthBrowserSessions::class);
    $current = $sessions->admit($user, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $next->getId(), browserSessionId: $current->identifier(), browserBinding: $binding);
    $grant = app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password'], RecentAuthenticationPurpose::SessionRevocation, $context)->reveal();
    $oldBrowser = BrowserSession::query()->whereKeyNot($current->identifier())->sole();
    $sessions->revoke($user, $oldBrowser->identifier(), $grant, $context);
    expect($replacement->refresh()->revoked_at)->not->toBeNull()->and($current->refresh()->revoked_at)->not->toBeNull();

});

it('rejects managed remember on a standard guard before creating authority', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $user = $this->user();
    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], ['remember' => true], auth()->guard('web'), app('session.store')))->toThrow(AuthException::class);
    expect(BrowserSession::query()->count())->toBe(0)->and(RememberCredential::query()->count())->toBe(0);
});

it('requires a fresh enrolled factor before admitting remembered primary proof', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.totp.enabled' => true, 'auth.guards.web.driver' => 'nvl-managed-session', 'session.secure' => true, 'session.http_only' => true]);
    auth()->forgetGuards();
    $user = $this->user();
    $secret = 'JBSWY3DPEHPK3PXP';
    TotpCredential::query()->create(['subject_type' => $user->getMorphClass(), 'subject_id' => $user->getKey(), 'name' => 'Authenticator', 'secret' => $secret, 'algorithm' => 'sha1', 'digits' => 6, 'period' => 30, 'allowed_drift' => 1, 'confirmed_at' => now()]);
    $totp = new Google2FA;
    $code = $totp->oathTotp($secret, intdiv(now()->timestamp, 30));
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], ['remember' => true], $guard, app('session.store'), ['code' => $code]);
    $cookie = collect(app('cookie')->getQueuedCookies())->first(fn ($cookie) => $cookie->getName() === $guard->getRecallerName());
    $fresh = new Store('remember-mfa', new ArraySessionHandler(120));
    $fresh->start();
    app()->instance('session.store', $fresh);
    app()->instance('request', Request::create('/private', 'GET', [], [$cookie->getName() => $cookie->getValue()]));
    auth()->forgetGuards();
    $guard = auth()->guard('web');
    expect($guard->user())->toBeNull()->and(BrowserSession::query()->count())->toBe(1)->and(app(AuthenticationSessions::class)->hasPendingSecondFactor($fresh))->toBeTrue();
    $this->travel(31)->seconds();
    $code = $totp->oathTotp($secret, intdiv(now()->timestamp, 30));
    app(AuthenticationSessions::class)->completeSecondFactor(['code' => $code], $guard, $fresh);
    expect($guard->id())->toBe($user->getAuthIdentifier())->and(BrowserSession::query()->count())->toBe(2);
});

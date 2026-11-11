<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\PrincipalSessionContainment;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

it('revokes other subject sessions while retaining only the admitted current session', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $user = $this->user();
    $bindings = [];
    foreach (range(1, 3) as $index) {
        $store = new Store('managed-'.$index, new ArraySessionHandler(120));
        $store->start();
        app()->instance('session.store', $store);
        auth()->forgetGuards();
        app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), $store);
        $bindings[] = $store->get(AuthBrowserSessions::bindingKey('web'));
    }
    $sessions = app(AuthBrowserSessions::class);
    $current = $sessions->admit($user, 'web', $bindings[2]);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $current->identifier(), browserBinding: $bindings[2]);
    $grant = app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password'], RecentAuthenticationPurpose::SessionRevocation, $context)->reveal();
    expect(fn () => $sessions->revokeOthers($user, 'web', BrowserSession::query()->whereKeyNot($current->identifier())->first()->identifier(), $grant, $context))->toThrow(AuthException::class);
    expect($sessions->revokeOthers($user, 'web', $current->identifier(), $grant, $context))->toBe(2);
    $sessions->admit($user, 'web', $bindings[2]);
    expect(fn () => $sessions->admit($user, 'web', $bindings[0]))->toThrow(AuthException::class);
});

it('does not physically delete another guard payload by a colliding bare user id', function (): void {
    config(['session.driver' => 'database', 'session.table' => 'shared_payloads']);
    Schema::create('shared_payloads', function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->string('user_id');
    });
    $user = $this->user();
    app('db')->table('shared_payloads')->insert(['id' => 'other-guard-session', 'user_id' => $user->getKey()]);
    app(PrincipalSessionContainment::class)->contain($user, 'disabled');
    expect(app('db')->table('shared_payloads')->where('id', 'other-guard-session')->exists())->toBeTrue();
});

it('keeps revocation transactional and denies grants issued to a subsequently revoked browser', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true]);
    $user = $this->user();
    $store = app('session.store');
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), $store);
    $sessions = app(AuthBrowserSessions::class);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $current = $sessions->admit($user, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $current->identifier(), browserBinding: $binding);
    $reauth = app(AuthReauthentication::class);
    $passwordGrant = $reauth->confirm($user, ['password' => 'correct-password'], RecentAuthenticationPurpose::PasswordChange, $context)->reveal();
    $revokeGrant = $reauth->confirm($user, ['password' => 'correct-password'], RecentAuthenticationPurpose::SessionRevocation, $context)->reveal();
    expect(fn () => $user->getConnection()->transaction(function () use ($sessions, $user, $revokeGrant, $context): void {
        $sessions->revokeAll($user, $revokeGrant, $context);
        throw new RuntimeException('rollback');
    }))->toThrow(RuntimeException::class);
    $sessions->admit($user, 'web', $binding);
    $sessions->revokeAll($user, $revokeGrant, $context);
    expect(fn () => app(AuthPasswords::class)->update($user, ['password' => 'AnotherPassword123', 'passwordConfirmation' => 'AnotherPassword123'], $passwordGrant, $context))->toThrow(AuthException::class);
});

it('keeps the acting browser signed in after its own security action and ends every other browser', function (string $action): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    $bindings = [];
    foreach (range(1, 2) as $index) {
        $store = new Store('acting-'.$index, new ArraySessionHandler(120));
        $store->start();
        app()->instance('session.store', $store);
        auth()->forgetGuards();
        app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), $store);
        $bindings[] = $store->get(AuthBrowserSessions::bindingKey('web'));
    }
    $sessions = app(AuthBrowserSessions::class);
    $current = $sessions->admit($user, 'web', $bindings[1]);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $current->identifier(), browserBinding: $bindings[1]);
    $grant = static fn (RecentAuthenticationPurpose $purpose): string => app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password'], $purpose, $context)->reveal();
    match ($action) {
        'totp enrollment' => app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $grant(RecentAuthenticationPurpose::FactorEnrollment), context: $context),
        'recovery regeneration' => app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $grant(RecentAuthenticationPurpose::RecoveryRegeneration), context: $context),
        'password change' => app(AuthPasswords::class)->update($user, ['password' => 'AnotherPassword123', 'passwordConfirmation' => 'AnotherPassword123'], $grant(RecentAuthenticationPurpose::PasswordChange), $context),
    };

    expect($sessions->admit($user, 'web', $bindings[1])->identifier())->toBe($current->identifier())
        ->and(fn () => $sessions->admit($user, 'web', $bindings[0]))->toThrow(AuthException::class);
})->with(['totp enrollment', 'recovery regeneration', 'password change']);

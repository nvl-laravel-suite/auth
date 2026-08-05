<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Actions\Audit\ShowAuthAuditAction;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Authentication\LogoutAction;
use Nvl\Auth\Actions\Authentication\RequestEmailVerificationAction;
use Nvl\Auth\Actions\Authentication\VerifyEmailAction;
use Nvl\Auth\Actions\Passwords\ConfirmPasswordAction;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Events\UserLoggedOut;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;

it('logs in and out through the configured Laravel stateful guard', function (): void {
    $user = $this->user();
    Event::fake([UserAuthenticated::class, UserLoggedOut::class]);
    $authenticated = app(LoginAction::class)->execute($user->email, 'correct-password');

    expect($authenticated->getAuthIdentifier())->toBe($user->getAuthIdentifier())
        ->and(Auth::guard('web')->check())->toBeTrue()
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->exists())->toBeTrue();

    app(LogoutAction::class)->execute();

    expect(Auth::guard('web')->check())->toBeFalse();
    Event::assertDispatched(UserAuthenticated::class);
    Event::assertDispatched(UserLoggedOut::class);
});

it('bounds untrusted audit request context', function (): void {
    $this->app->instance(AuthAuditContextProvider::class, new class implements AuthAuditContextProvider
    {
        public function ipAddress(): ?string
        {
            return str_repeat('1', 100);
        }

        public function userAgent(): ?string
        {
            return str_repeat('u', 2_000);
        }

        public function requestId(): ?string
        {
            return str_repeat('r', 200);
        }
    });

    $audit = app(AuthAuditRecorder::class)->record('context.test');

    expect($audit)->not->toBeNull()
        ->and(strlen((string) $audit?->ip_address))->toBe(64)
        ->and(strlen((string) $audit?->user_agent))->toBe(1_024)
        ->and(strlen((string) $audit?->request_id))->toBe(128);
});

it('confirms the current password through Laravel session authority', function (): void {
    $user = $this->user();
    $request = app('request');
    $request->setLaravelSession(app('session')->driver());

    expect(fn () => app(ConfirmPasswordAction::class)->execute($user, 'wrong-password'))
        ->toThrow(AuthException::class, 'invalid');

    app(ConfirmPasswordAction::class)->execute($user, 'correct-password');

    expect($request->session()->get('auth.password_confirmed_at'))->toBeInt()
        ->and(AuthAudit::query()->where('action', 'password.confirmed')->exists())->toBeTrue();
});

it('runs the login pipeline after credential resolution and logs out rejected subjects', function (): void {
    $user = $this->user();
    RejectLoginStage::$subject = null;
    config()->set('nvl-auth.pipelines.login', [RejectLoginStage::class]);

    expect(fn () => app(LoginAction::class)->execute($user->email, 'correct-password'))
        ->toThrow(AuthException::class, 'rejected');

    expect(RejectLoginStage::$subject?->identifier)->toBe((string) $user->getKey())
        ->and(Auth::guard('web')->check())->toBeFalse();
});

it('authorizes audit detail access with decrypted metadata', function (): void {
    $user = $this->user();
    app(LoginAction::class)->execute($user->email, 'correct-password');
    $audit = AuthAudit::query()->where('action', 'authentication.succeeded')->sole();

    expect(app(ShowAuthAuditAction::class)->execute($user, $audit)->is($audit))->toBeTrue()
        ->and($audit->metadata)->toBeArray();
});

it('emits verification data without sending and marks the host email verified', function (): void {
    config()->set('nvl-auth.features.email_verification.enabled', true);
    $user = $this->user();
    Event::fake([AuthDeliveryRequested::class]);

    app(RequestEmailVerificationAction::class)->execute($user, 'en');

    Event::assertDispatched(AuthDeliveryRequested::class, function (AuthDeliveryRequested $event) use ($user): bool {
        return $event->request->recipient === $user->email
            && $event->request->payload['subject_id'] === (string) $user->getKey();
    });

    expect(app(VerifyEmailAction::class)->execute($user))->toBeTrue()
        ->and($user->refresh()->hasVerifiedEmail())->toBeTrue()
        ->and(app(VerifyEmailAction::class)->execute($user))->toBeFalse();
});

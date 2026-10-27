<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Nvl\Auth\Contracts\AuthManagementAccess;
use Nvl\Auth\Contracts\PasswordPolicy;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthUsers;

beforeEach(function (): void {
    Event::fake([AuthDeliveryRequested::class]);
});

it('rejects a stale password after a broker reset for confirmation and replacement', function (): void {
    $user = $this->user('stale-password@example.test');
    $stale = $user->fresh();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);

    expect(fn () => app(AuthPasswords::class)->confirm($stale, ['password' => 'correct-password'], app('session')->driver()))->toThrow(AuthException::class)
        ->and(fn () => app(AuthPasswords::class)->update($stale, ['currentPassword' => 'correct-password', 'password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123']))->toThrow(AuthException::class)
        ->and(Hash::check('replacement-password', $user->fresh()->password))->toBeTrue();
});

it('requires separate authority for credential edits', function (): void {
    $actor = $this->user('management-actor@example.test');
    $user = $this->user('management-subject@example.test');
    app()->instance(AuthManagementAccess::class, new class implements AuthManagementAccess
    {
        public function allows(Authenticatable $actor, string $ability, mixed $target = null): bool
        {
            return $ability === 'nvl.auth.users.update';
        }
    });

    expect(fn () => app(AuthUsers::class)->update($actor, $user, ['password' => 'new-password-123']))->toThrow(AuthException::class);
    expect(fn () => app(AuthUsers::class)->update($actor, $user, ['emailVerified' => true]))->toThrow(AuthException::class);
});

it('clears verification when an administrator changes an email', function (): void {
    $actor = $this->user('email-actor@example.test');
    $user = $this->user('email-subject@example.test');
    $user->forceFill(['email_verified_at' => now()])->save();

    $updated = app(AuthUsers::class)->update($actor, $user, ['email' => 'changed@example.test']);
    expect($updated->email_verified_at)->toBeNull();
});

it('enforces the password policy and bcrypt byte boundary for password changes', function (): void {
    $user = $this->user('password-policy@example.test');
    $update = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $update('12345678901'))->toThrow(ValidationException::class)
        ->and(fn () => $update(str_repeat('x', 73)))->toThrow(ValidationException::class);
    $update('123456789012');
    expect(Hash::check('123456789012', $user->fresh()->password))->toBeTrue();
});

it('keeps the bcrypt byte limit with a replacement policy', function (): void {
    app()->instance(PasswordPolicy::class, new class implements PasswordPolicy
    {
        public function rules(): array
        {
            return ['min:1'];
        }
    });
    $user = $this->user('replacement-policy@example.test');
    $change = fn (string $password) => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => $password, 'passwordConfirmation' => $password]);
    expect(fn () => $change(str_repeat('😀', 19)))->toThrow(ValidationException::class);
    $change(str_repeat('😀', 18));
    expect(Hash::check(str_repeat('😀', 18), $user->fresh()->password))->toBeTrue();
});

it('rejects stale account deletion after a broker reset', function (): void {
    $user = $this->user('stale-delete@example.test');
    $stale = $user->fresh();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    expect(fn () => app(AuthUsers::class)->deleteOwnAccount($stale, ['currentPassword' => 'correct-password'], auth()->guard('web'), app('session')->driver()))->toThrow(AuthException::class)
        ->and($user->fresh()->trashed())->toBeFalse();
});

it('passes the locked canonical principal to an injected updater and rotates remember credentials', function (): void {
    $user = $this->user('custom-updater@example.test');
    $user->forceFill(['remember_token' => 'original-remember'])->save();
    $stale = $user->fresh();
    $user->forceFill(['name' => 'Canonical name'])->save();
    $stale->name = 'Untrusted name';
    $updater = new class implements PasswordUpdater
    {
        public ?string $seenName = null;

        public function update(CanResetPassword $subject, #[SensitiveParameter] string $password): void
        {
            $this->seenName = $subject->name;
            $subject->forceFill(['password' => Hash::make($password)])->save();
        }
    };
    app()->instance(PasswordUpdater::class, $updater);
    app(AuthPasswords::class)->update($stale, ['currentPassword' => 'correct-password', 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    expect($updater->seenName)->toBe('Canonical name')
        ->and($user->fresh()->remember_token)->not->toBe('original-remember')
        ->and(Hash::check('replacement-password', $user->fresh()->password))->toBeTrue();
});

it('continues to authenticate an existing short password', function (): void {
    $user = $this->user('legacy-short-password@example.test');
    $user->forceFill(['password' => Hash::make('short123')])->save();
    $authenticated = app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'short123'], [], auth()->guard('web'), app('session')->driver());
    expect($authenticated->getAuthIdentifier())->toBe($user->getAuthIdentifier());
});

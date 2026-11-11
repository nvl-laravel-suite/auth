<?php

declare(strict_types=1);

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Passwords\DatabaseTokenRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\AuthDoctor;
use Nvl\Auth\Services\AuthPasswords;

it('applies replaceable eligibility before reset delivery and credential mutation', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user('ineligible@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0] ?? null;

    $this->app->instance(AuthenticationEligibility::class, new class implements AuthenticationEligibility
    {
        public function assertEligible(Authenticatable $subject, AuthenticationPurpose $purpose): void
        {
            throw new AuthException('host_subject_ineligible', 'Host policy rejected the subject.', 422);
        }
    });

    expect(fn () => app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class, 'Host policy')
        ->and(Hash::check('correct-password', $user->refresh()->password))->toBeTrue();
    $rejections = AuthAudit::query()->where('action', 'password.reset_rejected');
    expect($rejections->count())->toBe(1)
        ->and($rejections->first()->metadata['reason'])->toBe('host_subject_ineligible');
    $connection = $user->getConnection();
    $connection->beginTransaction();
    expect(fn () => app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class)
        ->and($rejections->count())->toBe(2);
    $connection->rollBack();
    expect($rejections->count())->toBe(1);

    Event::fake([AuthDeliveryRequested::class]);
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    Event::assertNotDispatched(AuthDeliveryRequested::class);
});

it('rolls back credential and token consumption when the injected updater fails', function (): void {
    Event::fake([AuthDeliveryRequested::class, PasswordReset::class]);
    $user = $this->user('rollback-reset@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $token = $event->request->payload['token'];
    app()->instance(PasswordUpdater::class, new class implements PasswordUpdater
    {
        public function update(CanResetPassword $subject, string $password): void
        {
            $subject->forceFill(['password' => Hash::make($password)])->save();
            throw new RuntimeException('Updater failed.');
        }
    });
    expect(fn () => app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $token, 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(RuntimeException::class)
        ->and(Hash::check('correct-password', $user->fresh()->password))->toBeTrue()
        ->and(app('auth.password')->broker()->getRepository()->exists($user, $token))->toBeTrue();
    Event::assertNotDispatched(PasswordReset::class);
});

it('rejects a token repository using a different actual connection', function (): void {
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user('mismatched-reset@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $broker = app('auth.password')->broker();
    $repository = $broker->getRepository();
    config()->set('database.connections.other_reset', config('database.connections.testing'));
    $other = DB::connection('other_reset');
    (new ReflectionProperty(DatabaseTokenRepository::class, 'connection'))->setValue($repository, $other);
    expect(fn () => app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class, 'same connection')
        ->and(Hash::check('correct-password', $user->fresh()->password))->toBeTrue();
    Event::fake([AuthDeliveryRequested::class]);
    expect(fn () => app(AuthPasswords::class)->requestReset(['identifier' => $user->email]))->toThrow(AuthException::class, 'same connection');
    Event::assertNotDispatched(AuthDeliveryRequested::class);
});

it('defers reset events and rolls back reset tokens with an enclosing transaction', function (): void {
    Event::fake([AuthDeliveryRequested::class, PasswordReset::class]);
    $user = $this->user('outer-reset@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $token = $event->request->payload['token'];
    $connection = $user->getConnection();
    $connection->beginTransaction();
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $token, 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    Event::assertNotDispatched(PasswordReset::class);
    $connection->rollBack();
    expect(Hash::check('correct-password', $user->fresh()->password))->toBeTrue()
        ->and(app('auth.password')->broker()->getRepository()->exists($user, $token))->toBeTrue();
    Event::assertNotDispatched(PasswordReset::class);
});

it('emits the password reset event only after the enclosing transaction commits', function (): void {
    Event::fake([AuthDeliveryRequested::class, PasswordReset::class]);
    $user = $this->user('outer-commit-reset@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $connection = $user->getConnection();
    $connection->beginTransaction();
    app(AuthPasswords::class)->reset(['identifier' => $user->email, 'token' => $event->request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']);
    Event::assertNotDispatched(PasswordReset::class);
    $connection->commit();
    Event::assertDispatched(PasswordReset::class);
});

it('delivers the reset expiry Laravel\'s password broker enforces', function (): void {
    config(['auth.passwords.users.expire' => 15, 'nvl-auth.features.password.settings.reset_ttl_minutes' => 120]);
    app()->forgetInstance('auth.password');
    Event::fake([AuthDeliveryRequested::class]);
    $this->travelTo(now()->startOfSecond());
    $user = $this->user('truthful-expiry@example.test');
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $request = Event::dispatched(AuthDeliveryRequested::class)->first()[0]->request;
    $reset = ['identifier' => $user->email, 'token' => $request->payload['token'], 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password'];

    expect($request->expiresAt->equalTo(now()->addMinutes(15)))->toBeTrue();
    $this->travelTo($request->expiresAt->addSecond());
    expect(fn () => app(AuthPasswords::class)->reset($reset))->toThrow(AuthException::class, 'invalid or expired');
});

it('applies the password broker throttle to reset requests without revealing it', function (): void {
    config(['auth.passwords.users.throttle' => 60]);
    app()->forgetInstance('auth.password');
    Event::fake([AuthDeliveryRequested::class]);
    $this->travelTo(now()->startOfSecond());
    $user = $this->user('throttled-reset@example.test');
    $tokens = DB::table('nvl_auth_password_reset_tokens')->where('email', $user->email);

    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);
    $first = $tokens->first();
    $this->travel(59)->seconds();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
    $rejection = AuthAudit::query()->where('action', 'password.reset_rejected')->sole();
    expect($tokens->count())->toBe(1)
        ->and($tokens->first())->toEqual($first)
        ->and($rejection->outcome)->toBe('failure')
        ->and($rejection->metadata['reason'])->toBe('password_reset_throttled');

    $this->travel(1)->seconds();
    app(AuthPasswords::class)->requestReset(['identifier' => $user->email]);

    Event::assertDispatchedTimes(AuthDeliveryRequested::class, 2);
    expect($tokens->count())->toBe(1)
        ->and($tokens->first()->token)->not->toBe($first->token)
        ->and(AuthAudit::query()->where('action', 'password.reset_rejected')->count())->toBe(1);
});

it('warns only while a host still sets the unread reset lifetime', function (?int $setting, bool $passed): void {
    config(['auth.passwords.users.expire' => 15]);
    if ($setting !== null) {
        config(['nvl-auth.features.password.settings.reset_ttl_minutes' => $setting]);
    }

    expect(collect(app(AuthDoctor::class)->inspect())->firstWhere('name', 'configuration.password_reset_ttl'))
        ->toMatchArray(['passed' => $passed, 'severity' => 'warning']);
})->with(['package default' => [null, true], 'agreeing leftover' => [15, false], 'disagreeing leftover' => [60, false]]);

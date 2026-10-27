<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Tests\Fixtures\SecurityRace;

it('requires a current one use destination bound verification token', function (string $change): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();
    $user->forceFill(['email_verified_at' => null])->save();
    $service = app(AuthEmailVerification::class);
    $service->request($user);
    $event = Event::dispatched(AuthDeliveryRequested::class)->first()[0];
    $token = $event->request->payload['token'] ?? 'missing-native-proof';
    if ($change === 'email') {
        $user->newQuery()->whereKey($user->getKey())->update(['email' => 'changed@example.test', 'email_identity_hash' => hash('sha256', 'changed@example.test')]);
    } elseif ($change === 'revision') {
        $user->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'security_containment'));
    } elseif ($change === 'expiry') {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addHour());
    } elseif ($change === 'subject') {
        $user = $this->user('other@example.test');
    } elseif ($change === 'wrong') {
        $token = str_repeat('0', 64);
    } elseif ($change === 'replay') {
        expect($service->verify($user, $token))->toBeTrue();
    }
    expect(fn () => $service->verify($user, $token))->toThrow(AuthException::class);
})->with(['email', 'revision', 'expiry', 'subject', 'wrong', 'replay']);

it('rolls verification proof state audit and event back with the enclosing transaction', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    Event::fake([AuthDeliveryRequested::class, Verified::class]);
    $user = $this->user();
    $service = app(AuthEmailVerification::class);
    $service->request($user);
    $token = Event::dispatched(AuthDeliveryRequested::class)->first()[0]->request->payload['token'];
    expect(fn () => $user->getConnection()->transaction(function () use ($service, $user, $token): void {
        expect($service->verify($user, $token))->toBeTrue();
        Event::assertNotDispatched(Verified::class);
        throw new RuntimeException('rollback verification');
    }))->toThrow(RuntimeException::class, 'rollback verification');
    expect($user->fresh()->hasVerifiedEmail())->toBeFalse()
        ->and(AuthAudit::query()->where('action', 'email.verified')->count())->toBe(0);
    Event::assertNotDispatched(Verified::class);
    expect($service->verify($user, $token))->toBeTrue();
    Event::assertDispatchedTimes(Verified::class, 1);
});

it('spends a still valid proof without duplicate verification and persists bounded failed attempts', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    Event::fake([AuthDeliveryRequested::class, Verified::class]);
    $user = $this->user();
    $service = app(AuthEmailVerification::class);
    $service->request($user);
    $service->request($user);
    $tokens = Event::dispatched(AuthDeliveryRequested::class)->map(fn ($event) => $event[0]->request->payload['token'])->all();
    expect($service->verify($user, $tokens[0]))->toBeTrue()
        ->and($service->verify($user, $tokens[1]))->toBeFalse();
    Event::assertDispatchedTimes(Verified::class, 1);
    expect(fn () => $service->verify($user, $tokens[1]))->toThrow(AuthException::class);
    $user->forceFill(['email_verified_at' => null])->save();
    $service->request($user);
    $token = Event::dispatched(AuthDeliveryRequested::class)->last()[0]->request->payload['token'];
    [$id] = explode('.', $token);
    for ($i = 0; $i < 5; $i++) {
        expect(fn () => $service->verify($user, $id.'.'.str_repeat('0', 64)))->toThrow(AuthException::class);
    }
    expect(Challenge::findOrFail($id)->attempts)->toBe(5)
        ->and(fn () => $service->verify($user, $token))->toThrow(AuthException::class);
});

it('allows reissue only for the current destination after administrative email mutation', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();
    $service = app(AuthEmailVerification::class);
    $service->request($user);
    $old = Event::dispatched(AuthDeliveryRequested::class)->last()[0]->request->payload['token'];
    $updated = app(AuthUsers::class)->update($user, $user, ['email' => 'replacement@example.test']);
    expect(fn () => $service->verify($user, $old))->toThrow(AuthException::class);
    $service->request($updated);
    $new = Event::dispatched(AuthDeliveryRequested::class)->last()[0]->request->payload['token'];
    expect(fn () => $service->verify($user, $new))->toThrow(AuthException::class);
    expect($service->verify($updated, $new))->toBeTrue();
});

it('serializes verification behind a racing committed administrative email change', function (): void {
    config(['nvl-auth.features.email_verification.enabled' => true]);
    Event::fake([AuthDeliveryRequested::class]);
    $user = $this->user();
    app(AuthEmailVerification::class)->request($user);
    $token = Event::dispatched(AuthDeliveryRequested::class)->last()[0]->request->payload['token'];
    $gate = tempnam(sys_get_temp_dir(), 'email-verification-race-');
    try {
        $change = static function () use ($user, $gate): array {
            $user->getConnection()->transaction(function () use ($user, $gate): void {
                app(AuthUsers::class)->update($user, $user, ['email' => 'replacement@example.test']);
                file_put_contents($gate, 'changed');
                SecurityRace::wait(fn (): bool => file_get_contents($gate) === 'verifying');
            });

            return [];
        };
        $verify = static function () use ($user, $token, $gate): array {
            SecurityRace::wait(fn (): bool => file_get_contents($gate) === 'changed');
            file_put_contents($gate, 'verifying');
            try {
                app(AuthEmailVerification::class)->verify($user, $token);

                return ['verified' => true];
            } catch (AuthException) {
                return ['verified' => false];
            }
        };
        $results = SecurityRace::run([$change, $verify]);
        expect(array_column($results, 'ok'))->toBe([true, true], json_encode($results, JSON_THROW_ON_ERROR))
            ->and($results[1]['verified'])->toBeFalse()
            ->and($user->fresh()->email)->toBe('replacement@example.test')
            ->and($user->fresh()->hasVerifiedEmail())->toBeFalse();
    } finally {
        unlink($gate);
    }
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires MySQL/PostgreSQL.');

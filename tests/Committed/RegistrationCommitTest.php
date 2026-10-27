<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Registered;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalRegistered;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Tests\CommittedDeliveryTestCase;

uses(CommittedDeliveryTestCase::class);

beforeEach(function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open', 'nvl-auth.features.email_verification.enabled' => true]);
});

it('publishes registration and selected verification once only after the outer commit', function (bool $commit): void {
    Event::fake([Registered::class, PrincipalRegistered::class, AuthDeliveryRequested::class]);
    Mail::fake();
    DB::beginTransaction();
    $user = app(AuthRegistration::class)->register(['name' => 'Signup', 'email' => 'signup@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);
    Event::assertNotDispatched(PrincipalRegistered::class);
    Event::assertNotDispatched(AuthDeliveryRequested::class);
    if ($commit) {
        DB::commit();
        Event::assertDispatchedTimes(PrincipalRegistered::class, 1);
        Event::assertDispatchedTimes(AuthDeliveryRequested::class, 1);
        $fact = Event::dispatched(PrincipalRegistered::class)->sole()[0];
        expect($fact->subject->identifier)->toBe($user->getKey())
            ->and(json_encode($fact, JSON_THROW_ON_ERROR))->not->toContain('SecurePassword123')->not->toContain('signup@example.test');
        expect(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(1);
    } else {
        DB::rollBack();
        expect(User::query()->count())->toBe(0)->and(AuthAudit::query()->count())->toBe(0);
        Event::assertNotDispatched(PrincipalRegistered::class);
        Event::assertNotDispatched(AuthDeliveryRequested::class);
    }
    Event::assertNotDispatched(Registered::class);
    Mail::assertNothingSent();
})->with([true, false]);

it('does not report a committed listener failure as rolled back registration', function (): void {
    Event::listen(PrincipalRegistered::class, static function (): never {
        throw new RuntimeException('Listener failed after commit.');
    });
    expect(fn () => app(AuthRegistration::class)->register(['name' => 'Signup', 'email' => 'committed@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']))
        ->toThrow(RuntimeException::class, 'after commit');
    expect(User::query()->where('email', 'committed@example.test')->count())->toBe(1)
        ->and(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(1)->and(DB::transactionLevel())->toBe(0);
});

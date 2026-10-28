<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Events\PrincipalRegistered;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthRegistration;

it('keeps consumer owned onboarding atomic with native signup without authentication', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    Schema::create('consumer_onboarding', function (Blueprint $table): void {
        $table->uuid('user_id')->primary();
        $table->string('plan');
    });
    Event::fake([PrincipalRegistered::class]);
    expect(fn () => DB::transaction(function (): void {
        $user = app(AuthRegistration::class)->register(['name' => 'Onboard', 'email' => 'onboard@example.test', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);
        DB::table('consumer_onboarding')->insert(['user_id' => $user->getKey(), 'plan' => 'starter']);
        Event::assertNotDispatched(PrincipalRegistered::class);
        throw new RuntimeException('Onboarding failed.');
    }))->toThrow(RuntimeException::class, 'Onboarding failed');
    expect(User::query()->count())->toBe(0)->and(DB::table('consumer_onboarding')->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(0)->and(auth()->check())->toBeFalse();
    Event::assertNotDispatched(PrincipalRegistered::class);
});

<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Tests\Fixtures\SecurityRace;

it('reserves exactly one canonical principal under concurrent duplicate signup', function (): void {
    config(['nvl-auth.features.registration.enabled' => true, 'nvl-auth.features.registration.settings.mode' => 'open']);
    $signup = static function (): array {
        try {
            $user = app(AuthRegistration::class)->register(['name' => 'Race', 'email' => ' RACE@Example.Test ', 'password' => 'SecurePassword123', 'passwordConfirmation' => 'SecurePassword123']);

            return ['registered' => true, 'id' => $user->getKey()];
        } catch (AuthException $exception) {
            return ['registered' => false, 'code' => $exception->errorCode];
        }
    };
    $results = SecurityRace::run([$signup, $signup]);
    expect(array_column($results, 'ok'))->toBe([true, true], json_encode($results, JSON_THROW_ON_ERROR));
    expect(array_sum(array_column($results, 'registered')))->toBe(1)
        ->and(array_values(array_filter(array_column($results, 'code'))))->toBe(['registration_unavailable'])
        ->and(User::query()->where('email', 'race@example.test')->count())->toBe(1)
        ->and(AuthAudit::query()->where('action', 'registration.completed')->count())->toBe(1);
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed signup race requires MySQL/PostgreSQL.');

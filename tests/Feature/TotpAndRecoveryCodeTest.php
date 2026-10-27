<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Routing\Router;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Tests\Fixtures\Consumer\FeatureManifest;
use Nvl\Auth\Tests\Fixtures\Consumer\RouteServiceProvider;
use PragmaRX\Google2FA\Google2FA;

it('enrolls verifies and replay-protects totp credentials', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $enrollment = app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $code = app(Google2FA::class)->getCurrentOtp($enrollment->secret);
    $credential = app(AuthSecondFactor::class)->confirmEnrollment($user, $enrollment->credential, ['code' => $code], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect($credential->confirmed_at)->not->toBeNull()
        ->and(fn () => app(AuthSecondFactor::class)->verify($user, ['code' => $code]))
        ->toThrow(AuthException::class);

    expect(AuthAudit::query()->where('action', 'totp.failed')->where('outcome', 'failure')->exists())
        ->toBeTrue();
});

it('returns recovery codes once and consumes each hash once', function (): void {
    config()->set('nvl-auth.features.recovery_codes.enabled', true);
    $user = $this->user();
    $generated = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect($generated->codes)->toHaveCount(8)
        ->and(RecoveryCode::query()->count())->toBe(8);

    $record = app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => $generated->codes[0]]);

    expect($record->used_at)->not->toBeNull()
        ->and(fn () => app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => $generated->codes[0]]))
        ->toThrow(AuthException::class);
});

it('reads subject scoped totp lifecycle counts without decrypting secrets or changing state', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $other = $this->user('other@example.test');
    TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create();
    TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create(['confirmed_at' => null]);
    TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create(['revoked_at' => now()]);
    TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create(['confirmed_at' => null, 'revoked_at' => now()]);
    TotpCredential::factory()->forSubject($other)->state(['subject_type' => $other->getMorphClass()])->create();
    TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create(['subject_type' => 'another-principal']);
    $connection = (new TotpCredential)->getConnection();
    $connection->table((new TotpCredential)->getTable())->update(['secret' => 'not-a-decryptable-secret']);
    $before = $connection->table((new TotpCredential)->getTable())->orderBy('id')->get()->toJson();
    $audits = AuthAudit::query()->count();
    $connection->enableQueryLog();
    try {
        $state = app(AuthSecondFactor::class)->state($user);
        $queries = array_column($connection->getQueryLog(), 'query');
    } finally {
        $connection->disableQueryLog();
    }

    expect($state)->toBe(['confirmedCredentials' => 1, 'pendingEnrollments' => 1, 'revokedCredentials' => 2])
        ->and($connection->table((new TotpCredential)->getTable())->orderBy('id')->get()->toJson())->toBe($before)
        ->and(AuthAudit::query()->count())->toBe($audits);
    $credentialQueries = array_values(array_filter($queries, static fn (string $query): bool => str_contains($query, (new TotpCredential)->getTable())));
    expect($credentialQueries)->toHaveCount(1)
        ->and($credentialQueries[0])->not->toContain('secret', 'select *');
});

it('returns empty totp security state for an unenrolled principal', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    expect(app(AuthSecondFactor::class)->state($this->user()))
        ->toBe(['confirmedCredentials' => 0, 'pendingEnrollments' => 0, 'revokedCredentials' => 0]);
});

it('denies totp security state when its feature or dependency is disabled', function (string $key): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    config()->set($key, false);
    expect(fn () => app(AuthSecondFactor::class)->state($this->user()))->toThrow(AuthException::class);
})->with(['nvl-auth.enabled', 'nvl-auth.features.totp.enabled', 'nvl-auth.features.authentication.enabled']);

it('refuses totp state for an unavailable principal', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $user->delete();
    expect(fn () => app(AuthSecondFactor::class)->state($user))->toThrow(AuthException::class);
});

it('exposes totp state only for the authenticated subject with private read-only transport', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.account.enabled', true);
    config()->set('nvl-auth.features.totp.routes.account.enabled', true);
    app()->instance('routes.cached', false);
    (new RouteServiceProvider(app()))->boot(app(Router::class), app(AuthConfiguration::class), app(FeatureManifest::class), app(FeatureGate::class));
    $user = $this->user();
    $other = $this->user('other-http@example.test');
    TotpCredential::factory()->forSubject($other)->state(['subject_type' => $other->getMorphClass()])->create();

    $this->getJson('/nvl/api/v1/auth/totp')->assertUnauthorized();
    $before = AuthAudit::query()->count();
    $this->actingAs($user)->getJson('/nvl/api/v1/auth/totp?subject_id='.$other->id)
        ->assertOk()
        ->assertJsonPath('data', ['confirmedCredentials' => 0, 'pendingEnrollments' => 0, 'revokedCredentials' => 0])
        ->assertJsonMissingPath('data.secret')
        ->assertJsonMissingPath('data.provisioningUri')
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Referrer-Policy', 'no-referrer');
    expect(TotpCredential::query()->count())->toBe(1)
        ->and(AuthAudit::query()->count())->toBe($before);
});

it('restarts pending enrollment with fresh one-time material and preserves confirmed and other subject credentials', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $other = $this->user('other-restart@example.test');
    $confirmed = TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create();
    $revokedPending = TotpCredential::factory()->forSubject($user)->state(['subject_type' => $user->getMorphClass()])->create(['confirmed_at' => null, 'revoked_at' => now()]);
    $foreign = TotpCredential::factory()->forSubject($other)->state(['subject_type' => $other->getMorphClass()])->create(['confirmed_at' => null]);
    $original = app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $replacement = app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect($replacement->credential->getKey())->not->toBe($original->credential->getKey())
        ->and($replacement->secret)->not->toBe($original->secret)
        ->and($original->credential->fresh())->toBeNull()
        ->and($confirmed->fresh())->not->toBeNull()
        ->and($revokedPending->fresh())->not->toBeNull()
        ->and($foreign->fresh())->not->toBeNull();
    expect(fn () => app(AuthSecondFactor::class)->confirmEnrollment($user, $original->credential, ['code' => app(Google2FA::class)->getCurrentOtp($original->secret)], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(ModelNotFoundException::class);
});

it('uses the configured auth guard for totp state without falling back to a different signed-in principal', function (array $middleware, bool $requiresWeb): void {
    config([
        'nvl-auth.features.totp.enabled' => true,
        'nvl-auth.routes.enabled' => true,
        'nvl-auth.routes.account.enabled' => true,
        'nvl-auth.features.totp.routes.account.enabled' => true,
        'nvl-auth.routes.account.middleware' => $middleware,
        'nvl-auth.guard' => 'security',
        'auth.guards.security' => ['driver' => 'session', 'provider' => 'users'],
    ]);
    app()->instance('routes.cached', false);
    (new RouteServiceProvider(app()))->boot(app(Router::class), app(AuthConfiguration::class), app(FeatureManifest::class), app(FeatureGate::class));
    $web = $this->user('web-guard@example.test');
    $security = $this->user('security-guard@example.test');
    TotpCredential::factory()->forSubject($security)->state(['subject_type' => $security->getMorphClass()])->create();

    $this->getJson('/nvl/api/v1/auth/totp')->assertUnauthorized();
    $this->actingAs($web, 'web')->getJson('/nvl/api/v1/auth/totp')->assertUnauthorized();
    $this->actingAs($security, 'security')->getJson('/nvl/api/v1/auth/totp')
        ->assertOk()->assertJsonPath('data.confirmedCredentials', 1);

    auth()->guard('web')->forgetUser();
    auth()->shouldUse('web');
    $response = $this->getJson('/nvl/api/v1/auth/totp');
    if ($requiresWeb) {
        $response->assertUnauthorized();
    } else {
        $response->assertOk()->assertJsonPath('data.confirmedCredentials', 1);
    }
})->with([
    'default account middleware' => [['auth', 'throttle:nvl.auth.account'], false],
    'custom account middleware' => [['throttle:nvl.auth.account'], false],
    'explicit host guard' => [['auth:web', 'throttle:nvl.auth.account'], true],
]);

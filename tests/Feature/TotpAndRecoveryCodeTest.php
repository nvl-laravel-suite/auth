<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\Authentication;
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
    expect(app(AuthSecondFactor::class)->state($user))
        ->toBe(['confirmedCredentials' => 0, 'pendingEnrollments' => 0, 'revokedCredentials' => 0]);

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
    $this->travelTo(CarbonImmutable::parse('2026-01-01 12:00:05 UTC'));
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
        'nvl-auth.authorization.guard' => 'security',
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
        $route = app(Router::class)->getRoutes()->match(Request::create('/nvl/api/v1/auth/totp'));
        expect(app(Router::class)->gatherRouteMiddleware($route))->toContain(Authenticate::class.':web');
        $response->assertUnauthorized();
    } else {
        $response->assertOk()->assertJsonPath('data.confirmedCredentials', 1);
    }
})->with([
    'default account middleware' => [['auth', 'throttle:nvl.auth.account'], false],
    'custom account middleware' => [['throttle:nvl.auth.account'], false],
    'explicit host guard' => [['auth:web', 'throttle:nvl.auth.account'], true],
]);

it('shares one factor attempt budget across every unexpired proof of a principal', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $credential = TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    $login = app(Authentication::class);
    $guard = auth()->guard('web');
    $session = app('session.store');
    $this->freezeSecond();
    $current = static fn (): string => app(Google2FA::class)->oathTotp($credential->secret, intdiv(now()->getTimestamp(), 30));
    $wrong = collect(range(0, 9))->map(static fn (int $digit): string => str_repeat((string) $digit, 6))
        ->first(static fn (string $code): bool => app(Google2FA::class)->verifyKey($credential->secret, $code, 2, intdiv(now()->getTimestamp(), 30)) === false);

    for ($attempt = 1; $attempt <= 5; $attempt++) {
        expect(fn () => $login->login($credentials, [], $guard, $session, ['code' => $wrong]))->toThrow(AuthException::class, 'The TOTP code is invalid.');
    }

    try {
        $login->login($credentials, [], $guard, $session, ['code' => $current()]);
        $this->fail('A sixth factor attempt was admitted through a fresh password proof.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('authentication_proof_invalid');
    }

    expect($guard->check())->toBeFalse()
        ->and($credential->refresh()->last_accepted_timestep)->toBeNull()
        ->and((int) Challenge::query()->where('type', 'authentication_proof')->sum('attempts'))->toBe(5);

    $this->travel(301)->seconds();

    expect($login->login($credentials, [], $guard, $session, ['code' => $current()])->getAuthIdentifier())->toBe($user->getKey());
});

it('accepts totp codes only inside the stored drift window and never at or before the accepted timestep', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $credential = TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $this->freezeSecond();
    $timestep = intdiv(now()->getTimestamp(), 30);
    $code = static fn (int $step): string => app(Google2FA::class)->oathTotp($credential->secret, $step);
    $verify = static fn (int $step): TotpCredential => app(AuthSecondFactor::class)->verify($user, ['code' => $code($step)]);

    expect($credential->getRawOriginal('secret'))->not->toContain($credential->secret)
        ->and(fn () => $verify($timestep - 2))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and(fn () => $verify($timestep + 2))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and($verify($timestep)->last_accepted_timestep)->toBe($timestep)
        ->and(fn () => $verify($timestep))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and(fn () => $verify($timestep - 1))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and($verify($timestep + 1)->last_accepted_timestep)->toBe($timestep + 1);
});

it('stores only keyed recovery code hashes and scopes consumption to the owning principal', function (): void {
    config()->set('nvl-auth.features.recovery_codes.enabled', true);
    $user = $this->user();
    $other = $this->user('recovery-other@example.test');
    $generated = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $stored = json_encode(DB::table((new RecoveryCode)->getTable())->get(), JSON_THROW_ON_ERROR);

    foreach ($generated->codes as $code) {
        expect($stored)->not->toContain($code)
            ->and($stored)->not->toContain(hash('sha256', $code));
    }

    expect(fn () => app(AuthSecondFactor::class)->consumeRecoveryCode($other, ['code' => $generated->codes[0]]))->toThrow(AuthException::class, 'The recovery code is invalid.')
        ->and(app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => ' '.mb_strtolower($generated->codes[0]).' '])->used_at)->not->toBeNull()
        ->and(RecoveryCode::query()->whereNotNull('used_at')->count())->toBe(1);

    app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect(fn () => app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => $generated->codes[1]]))->toThrow(AuthException::class, 'The recovery code is invalid.');
});

it('never writes factor secrets or codes to the audit trail', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    config()->set('nvl-auth.features.recovery_codes.enabled', true);
    $user = $this->user();
    $this->freezeSecond();
    $enrollment = app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $timestep = intdiv(now()->getTimestamp(), 30);
    $confirmation = app(Google2FA::class)->oathTotp($enrollment->secret, $timestep);
    app(AuthSecondFactor::class)->confirmEnrollment($user, $enrollment->credential, ['code' => $confirmation], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $replayed = fn () => app(AuthSecondFactor::class)->verify($user, ['code' => $confirmation]);
    $this->travel(30)->seconds();
    $next = app(Google2FA::class)->oathTotp($enrollment->secret, intdiv(now()->getTimestamp(), 30));
    $generated = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => $generated->codes[0]]);

    expect($replayed)->toThrow(AuthException::class);

    $audits = AuthAudit::query()->get();
    $trail = json_encode($audits->map(static fn (AuthAudit $audit): array => [$audit->action, $audit->outcome, $audit->metadata])->all(), JSON_THROW_ON_ERROR);

    expect($audits->pluck('action')->all())->toContain('totp.enrolled', 'totp.failed', 'recovery_codes.regenerated', 'recovery_code.used');

    foreach ([$enrollment->secret, $confirmation, $next, 'correct-password', $user->getAuthPassword(), ...$generated->codes] as $secret) {
        expect($trail)->not->toContain($secret);
    }
});

it('confirms only the owning principal pending enrollment with a valid code', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $other = $this->user('totp-other@example.test');
    $this->freezeSecond();
    $enrollment = app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $code = app(Google2FA::class)->oathTotp($enrollment->secret, intdiv(now()->getTimestamp(), 30));

    expect(fn () => app(AuthSecondFactor::class)->confirmEnrollment($other, $enrollment->credential, ['code' => $code], grant: $this->recentGrant($other, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'The TOTP credential is unavailable.')
        ->and(fn () => app(AuthSecondFactor::class)->confirmEnrollment($user, $enrollment->credential, ['code' => app(Google2FA::class)->oathTotp($enrollment->secret, intdiv(now()->getTimestamp(), 30) + 5)], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and(fn () => app(AuthSecondFactor::class)->verify($user, ['code' => $code]))->toThrow(AuthException::class, 'The TOTP code is invalid.')
        ->and($enrollment->credential->refresh()->confirmed_at)->toBeNull()
        ->and(app(AuthSecondFactor::class)->confirmEnrollment($user, $enrollment->credential, ['code' => $code], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext())->confirmed_at)->not->toBeNull();
});

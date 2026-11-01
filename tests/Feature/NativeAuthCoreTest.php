<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Contracts\AuthPipelineStage;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Models\User;
use Nvl\Auth\Results\IssuedApiToken;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationProofs;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthMaintenance;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\PrincipalEmailIdentity;
use Nvl\Auth\Services\PrincipalEmailIdentityAdoption;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthenticationVerification;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use PragmaRX\Google2FA\Google2FA;

it('preserves host and runtime hidden attributes alongside mapped authentication secrets', function (): void {
    config(['nvl-auth.features.principal_management.settings.attributes.password' => 'credential_hash']);
    $user = new class extends User
    {
        /** @var list<string> */
        protected $hidden = ['host_secret'];
    };
    $user->setRawAttributes([
        'name' => 'Visible name',
        'credential_hash' => 'credential-secret',
        'host_secret' => 'host-secret',
        'session_secret' => 'runtime-secret',
    ]);
    $user->makeHidden('session_secret');

    expect($user->toArray())->toBe(['name' => 'Visible name'])
        ->and($user->getHidden())->toContain('credential_hash', 'host_secret', 'session_secret');
});

it('publishes explicit native credential and session contracts', function (): void {
    foreach ([
        [Authentication::class, 'verifyCredentials', ['array'], Authenticatable::class],
        [Authentication::class, 'login', ['array', 'array', StatefulGuard::class, Session::class, 'array'], Authenticatable::class],
        [AuthenticationSessions::class, 'establishFromProof', ['string', StatefulGuard::class, Session::class, AuthenticationRequestContext::class, 'bool'], Authenticatable::class],
    ] as [$class, $method, $parameters, $return]) {
        $reflection = new ReflectionMethod($class, $method);
        expect(array_map(static fn (ReflectionParameter $parameter): string => (string) $parameter->getType(), $reflection->getParameters()))->toBe($parameters)
            ->and((string) $reflection->getReturnType())->toBe($return);
    }
});

it('consumes native challenges with committed attempts and exact protocol bindings', function (): void {
    config(['nvl-auth.features.security_codes.enabled' => true, 'nvl-auth.features.magic_links.enabled' => true]);
    $challenges = app(AuthChallenges::class);
    $issued = $challenges->issue(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', CarbonImmutable::now()->addMinutes(5), numeric: true, maxAttempts: 2);
    $secret = $issued['secret'];
    expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', $secret === '000000' ? '111111' : '000000'))->toThrow(AuthException::class);
    expect($issued['challenge']->refresh()->attempts)->toBe(1);
    expect(fn () => $challenges->consumeById(AuthFeature::MagicLinks, AuthMessageType::MagicLink, $issued['challenge']->identifier(), 'login', $secret))->toThrow(AuthException::class);
    expect($issued['challenge']->refresh()->consumed_at)->toBeNull();
    $consumed = $challenges->consumeById(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, $issued['challenge']->identifier(), 'login', $secret);
    expect($consumed->consumed_at)->not->toBeNull()
        ->and($consumed->toArray())->not->toHaveKeys(['secret_hash', 'secondary_secret_hash'])
        ->and(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'native@example.test', 'login', $secret))->toThrow(AuthException::class);
});

it('keeps challenge SQL expiry and failed attempts on UTC instants under host timezones', function (string $timezone): void {
    $original = date_default_timezone_get();
    date_default_timezone_set($timezone);
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25T12:00:00Z'));
    try {
        config(['app.timezone' => $timezone, 'nvl-auth.features.security_codes.enabled' => true]);
        $challenges = app(AuthChallenges::class);
        $issued = $challenges->issue(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', CarbonImmutable::now($timezone)->addMinute(), numeric: true);
        expect(CarbonImmutable::parse($issued['challenge']->getRawOriginal('expires_at'), 'UTC')->utc()->toIso8601String())->toBe('2026-10-25T12:01:00+00:00');
        expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', 'wrong'))->toThrow(AuthException::class);
        expect($issued['challenge']->refresh()->attempts)->toBe(1);
        CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-10-25T12:02:00Z'));
        expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'clock@example.test', 'login', $issued['secret']))->toThrow(AuthException::class);
        expect($issued['challenge']->refresh()->active_key)->toBeNull()
            ->and($issued['challenge']->consumed_at)->toBeNull()
            ->and($issued['challenge']->attempts)->toBe(1);
    } finally {
        CarbonImmutable::setTestNow();
        date_default_timezone_set($original);
    }
})->with(['Europe/Sofia', 'America/New_York']);

it('enforces the challenge attempt ceiling in a non UTC PostgreSQL session', function (string $timezone): void {
    $connection = DB::connection();
    if ($connection->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('PostgreSQL session timezone regression.');
    }
    $original = $connection->scalar('SHOW TimeZone');
    try {
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$timezone]);
        config(['nvl-auth.features.security_codes.enabled' => true]);
        $challenges = app(AuthChallenges::class);
        $issued = $challenges->issue(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'attempts@example.test', 'login', CarbonImmutable::now('UTC')->addMinutes(10), numeric: true, maxAttempts: 2);
        $wrong = $issued['secret'] === '000000' ? '111111' : '000000';
        foreach ([1, 2] as $attempts) {
            expect(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'attempts@example.test', 'login', $wrong))->toThrow(AuthException::class);
            expect($issued['challenge']->refresh()->attempts)->toBe($attempts);
        }
        expect($issued['challenge']->active_key)->toBeNull()
            ->and(fn () => $challenges->consume(AuthFeature::SecurityCodes, AuthMessageType::SecurityCode, 'attempts@example.test', 'login', $issued['secret']))->toThrow(AuthException::class);
    } finally {
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$original]);
    }
})->with(['Europe/Sofia', 'America/New_York']);

it('uses exact invitation expiry and retention boundaries in a non UTC PostgreSQL session', function (string $timezone): void {
    $connection = DB::connection();
    if ($connection->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('PostgreSQL session timezone regression.');
    }
    $original = $connection->scalar('SHOW TimeZone');
    try {
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$timezone]);
        $now = CarbonImmutable::parse('2026-11-01T12:00:00Z');
        $this->travelTo($now);
        config(['nvl-auth.features.invitations.enabled' => true, 'nvl-auth.cleanup.retention_days' => 30]);
        Event::fake([AuthDeliveryRequested::class]);
        $actor = $this->user();
        $invitations = app(AuthInvitations::class);
        $expired = $invitations->create(['recipient' => 'expired@example.test'], $actor, new InvitationIssuanceContext(expiresAt: $now->addMinute()))['invitation'];
        $active = $invitations->create(['recipient' => 'active@example.test'], $actor, new InvitationIssuanceContext(expiresAt: $now->addMinutes(3)))['invitation'];
        $this->travelTo($now->addMinutes(2));
        expect($invitations->findActive('expired@example.test', 'registration', authority: $actor))->toBeNull()
            ->and($invitations->findActive('active@example.test', 'registration', authority: $actor)?->identifier())->toBe($active->identifier())
            ->and($invitations->paginate($actor, ['lifecycle' => 'expired'])->modelKeys())->toBe([$expired->identifier()])
            ->and($invitations->paginate($actor, ['lifecycle' => 'active'])->modelKeys())->toBe([$active->identifier()])
            ->and($invitations->paginate($actor, ['expiresAfter' => $now->addMinutes(2)->toIso8601String(), 'expiresBefore' => $now->addMinutes(4)->toIso8601String()])->modelKeys())->toBe([$active->identifier()]);

        $cutoff = $now->addMinutes(2)->subDays(30);
        $old = Invitation::factory()->create(['expires_at' => $cutoff->subMinute()]);
        $retained = Invitation::factory()->create(['expires_at' => $cutoff->addMinute()]);
        $maintenance = app(AuthMaintenance::class);
        expect($maintenance->prune($actor, true)['invitations'])->toBe(1)
            ->and(Invitation::query()->whereKey($old->identifier())->exists())->toBeTrue();
        expect($maintenance->prune($actor)['invitations'])->toBe(1)
            ->and(Invitation::query()->whereKey($old->identifier())->exists())->toBeFalse()
            ->and(Invitation::query()->whereKey($retained->identifier())->exists())->toBeTrue();
    } finally {
        $this->travelBack();
        $connection->selectOne("SELECT set_config('TimeZone', ?, false)", [$original]);
    }
})->with(['Europe/Sofia', 'America/New_York']);

it('verifies credentials without logging in and completes login with the supplied guard and session', function (): void {
    $user = $this->user('native-login@example.test');
    $guard = auth()->guard('web');
    $session = app('session.store');
    $session->start();
    $before = $session->getId();
    $authentication = app(Authentication::class);
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    expect($authentication->verifyCredentials($credentials)->getAuthIdentifier())->toBe($user->id)
        ->and($guard->check())->toBeFalse();
    $authenticated = $authentication->login($credentials, [], $guard, $session);
    expect($authenticated->getAuthIdentifier())->toBe($user->id)
        ->and($guard->id())->toBe($user->id)
        ->and($session->getId())->not->toBe($before);
});

it('completes stateless token login without using or clearing an existing browser session', function (): void {
    config(['nvl-auth.features.sessions.enabled' => false]);
    $browser = $this->user('browser@example.test');
    $user = $this->user('stateless@example.test');
    $guard = auth()->guard('web');
    $guard->login($browser);
    $session = app('session.store');
    $session->put('host-state', 'preserved');
    $before = $session->all();
    $sessionId = $session->getId();
    Event::fake([UserAuthenticated::class]);

    $result = app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
        ['ipAddress' => '203.0.113.11'],
    );

    expect($result['subject']->getAuthIdentifier())->toBe($user->id)
        ->and($result['token']->plainTextToken)->not->toBeEmpty()
        ->and($user->tokens()->count())->toBe(1)
        ->and($user->refresh()->last_login_ip)->toBe('203.0.113.11')
        ->and($user->last_login_at)->not->toBeNull()
        ->and($guard->id())->toBe($browser->id)
        ->and($session->all())->toBe($before)
        ->and($session->getId())->toBe($sessionId)
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(1);
    Event::assertDispatchedTimes(UserAuthenticated::class, 1);
});

it('requires native factor proof before stateless success and never issues a token for missing invalid or replayed proof', function (): void {
    config(['nvl-auth.features.totp.enabled' => true]);
    $user = $this->user();
    $credential = TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    $token = ['name' => 'Native mobile', 'abilities' => ['profile:read']];
    $login = app(Authentication::class);
    Event::fake([UserAuthenticated::class]);

    expect(fn () => $login->loginWithToken($credentials, $token))->toThrow(AuthException::class, 'second factor')
        ->and(fn () => $login->loginWithToken($credentials, $token, [], ['code' => 'invalid']))->toThrow(AuthException::class)
        ->and($user->tokens()->count())->toBe(0)
        ->and($user->refresh()->last_login_at)->toBeNull();
    Event::assertNotDispatched(UserAuthenticated::class);
    $code = app(Google2FA::class)->getCurrentOtp($credential->secret);
    $result = $login->loginWithToken($credentials, $token, [], ['code' => $code]);
    expect($result['subject']->getAuthIdentifier())->toBe($user->id)
        ->and($user->tokens()->count())->toBe(1)
        ->and(fn () => $login->loginWithToken($credentials, $token, [], ['code' => $code]))->toThrow(AuthException::class)
        ->and($user->tokens()->count())->toBe(1);
    Event::assertDispatchedTimes(UserAuthenticated::class, 1);
});

it('runs the configured login pipeline for stateless authentication before any success', function (): void {
    $user = $this->user();
    config(['nvl-auth.pipelines.login' => [RejectLoginStage::class]]);
    RejectLoginStage::$subject = null;
    Event::fake([UserAuthenticated::class, AuthenticationRejected::class]);

    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(AuthException::class, 'rejected');
    expect(RejectLoginStage::$subject?->identifier)->toBe($user->id)
        ->and($user->tokens()->count())->toBe(0)
        ->and($user->refresh()->last_login_at)->toBeNull();
    Event::assertNotDispatched(UserAuthenticated::class);
    Event::assertDispatched(AuthenticationRejected::class);
});

it('rejects persisted eligibility credential and identity changes made by a stateless login pipeline', function (string $change): void {
    $user = $this->user();
    $other = $this->user('replacement@example.test');
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use ($user, $other, $change): mixed {
        $result = $next($context);
        match ($change) {
            'inactive' => $user->forceFill(['is_active' => false])->save(),
            'locked' => $user->forceFill(['locked_until' => now()->addHour()])->save(),
            'deleted' => $user->delete(),
            'password' => $user->forceFill(['password' => 'replacement-password'])->save(),
            'substituted' => null,
        };

        return $change === 'substituted' ? $other : $result;
    });
    Event::fake([UserAuthenticated::class]);

    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(AuthException::class)
        ->and($user->tokens()->count())->toBe(0)
        ->and($other->tokens()->count())->toBe(0)
        ->and($user->fresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(0);
    Event::assertNotDispatched(UserAuthenticated::class);
})->with(['inactive', 'locked', 'deleted', 'password', 'substituted']);

it('rolls back stateless token metadata and success facts when token pipeline callbacks fail', function (): void {
    $user = $this->user();
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next): mixed {
        $next($context);
        throw new RuntimeException('Token postcondition rejected');
    }, 'api_token_issued');
    Event::fake([UserAuthenticated::class]);

    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(RuntimeException::class, 'postcondition')
        ->and($user->tokens()->count())->toBe(0)
        ->and($user->fresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->whereIn('action', ['api_token.issued', 'authentication.succeeded'])->count())->toBe(0);
    Event::assertNotDispatched(UserAuthenticated::class);
});

it('requires factor proof when a native enrollment becomes active inside the stateless pipeline', function (): void {
    config(['nvl-auth.features.totp.enabled' => true]);
    $user = $this->user();
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use ($user): mixed {
        TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);

        return $next($context);
    });
    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(AuthException::class, 'second factor')
        ->and($user->tokens()->count())->toBe(0);
});

it('accepts one native recovery proof for stateless login and rejects its reuse', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    $token = ['name' => 'Recovery device', 'abilities' => ['profile:read']];
    $proof = ['recoveryCode' => $recovery->codes[0]];
    $login = app(Authentication::class);
    expect($login->loginWithToken($credentials, $token, [], $proof)['subject']->getAuthIdentifier())->toBe($user->id)
        ->and(fn () => $login->loginWithToken($credentials, $token, [], $proof))->toThrow(AuthException::class)
        ->and($user->tokens()->count())->toBe(1);
});

it('rejects protected stateless context and conflicting or invalid factor input before issuing tokens', function (array $context, array $proof): void {
    $user = $this->user();
    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']], $context, $proof,
    ))->toThrow(InvalidArgumentException::class)
        ->and($user->tokens()->count())->toBe(0);
})->with([
    'session selector' => [['remember' => true], []],
    'owner selector' => [['requestedOwner' => null], []],
    'unknown factor' => [[], ['verified' => true]],
    'both proofs' => [[], ['code' => '123456', 'recoveryCode' => 'RECOVERY']],
    'empty proof' => [[], ['code' => '']],
    'non string proof' => [[], ['code' => 123456]],
]);

/** Configure a real host pipeline extension around the native stateless operation. */
function nativeStatelessStage(Closure $callback, string $pipeline = 'login'): void
{
    $stage = new NativeStatelessTestStage($callback);
    app()->instance($stage::class, $stage);
    config(["nvl-auth.pipelines.{$pipeline}" => [$stage::class]]);
}

/** Test-owned real pipeline extension; named so Laravel does not parse an anonymous class path as pipe arguments. */
final class NativeStatelessTestStage implements AuthPipelineStage
{
    public function __construct(private Closure $callback) {}

    public function handle(AuthPipelineContext $context, Closure $next): mixed
    {
        return ($this->callback)($context, $next);
    }
}

it('rolls back stateless issuance if the configured login metadata recorder fails', function (): void {
    $user = $this->user();
    app()->instance(SuccessfulLoginMetadataRecorder::class, new class implements SuccessfulLoginMetadataRecorder
    {
        public function record(Authenticatable $subject, AuthenticationRequestContext $context): void
        {
            throw new RuntimeException('Host metadata failed');
        }
    });
    Event::fake([UserAuthenticated::class]);
    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(RuntimeException::class, 'Host metadata failed')
        ->and($user->tokens()->count())->toBe(0)
        ->and($user->fresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->whereIn('action', ['api_token.issued', 'authentication.succeeded'])->count())->toBe(0);
    Event::assertNotDispatched(UserAuthenticated::class);
});

it('fails closed for token adapters without source transaction participation', function (): void {
    $user = $this->user();
    app()->instance(ApiTokenManager::class, Mockery::mock(ApiTokenManager::class));
    expect(fn () => app(Authentication::class)->loginWithToken(
        ['identifier' => $user->email, 'password' => 'correct-password'],
        ['name' => 'Native mobile', 'abilities' => ['profile:read']],
    ))->toThrow(AuthException::class, 'TransactionalApiTokenManager')
        ->and($user->tokens()->count())->toBe(0)
        ->and($user->fresh()->last_login_at)->toBeNull();
});

it('requires native enrolled proof before stateful success and consumes the server session continuation once', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $login = app(Authentication::class);
    $session = app('session.store');
    $session->start();
    $guard = auth()->guard('web');
    Event::fake([UserAuthenticated::class, AuthenticationRejected::class]);

    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], ['remember' => true, 'ipAddress' => '203.0.113.20'], $guard, $session))
        ->toThrow(AuthException::class, 'second factor')
        ->and($login->hasPendingSecondFactor($session))->toBeTrue()
        ->and($guard->check())->toBeFalse()
        ->and($user->fresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', 'authentication.factor_required')->count())->toBe(1)
        ->and(AuthAudit::query()->where('action', 'authentication.factor_required')->first()->subject_id)->toBe($user->id)
        ->and(AuthAudit::query()->whereIn('action', ['authentication.failed', 'authentication.rejected'])->count())->toBe(0);
    Event::assertNotDispatched(UserAuthenticated::class);
    Event::assertNotDispatched(AuthenticationRejected::class);
    expect(fn () => $login->completeSecondFactor(['code' => 'invalid'], $guard, $session))->toThrow(AuthException::class)
        ->and($guard->check())->toBeFalse();
    $authenticated = $login->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], $guard, $session);
    expect($authenticated->getAuthIdentifier())->toBe($user->id)
        ->and($guard->id())->toBe($user->id)
        ->and($login->hasPendingSecondFactor($session))->toBeFalse()
        ->and($user->fresh()->last_login_ip)->toBe('203.0.113.20')
        ->and(fn () => $login->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], $guard, $session))->toThrow(AuthException::class);
    Event::assertDispatchedTimes(UserAuthenticated::class, 1);
    expect(AuthAudit::query()->where('action', 'authentication.factor_required')->count())->toBe(1);
    $audit = AuthAudit::query()->where('action', 'authentication.factor_required')->firstOrFail();
    expect($audit->actor_id)->toBe($user->id)->and($audit->metadata)->toBeEmpty();
});

it('rejects stateful credential identity eligibility and password changes after the configured login pipeline', function (string $change): void {
    $user = $this->user();
    $other = $this->user('stateful-other@example.test');
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use ($user, $other, $change): mixed {
        $result = $next($context);
        match ($change) {
            'inactive' => $user->forceFill(['is_active' => false])->save(),
            'locked' => $user->forceFill(['locked_until' => now()->addHour()])->save(),
            'password' => $user->forceFill(['password' => 'replacement-password'])->save(),
            'substituted' => null,
        };

        return $change === 'substituted' ? $other : $result;
    });
    Event::fake([UserAuthenticated::class]);
    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store')))
        ->toThrow(AuthException::class)
        ->and(auth()->guard('web')->check())->toBeFalse()
        ->and($user->fresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(0);
    Event::assertNotDispatched(UserAuthenticated::class);
})->with(['inactive', 'locked', 'password', 'substituted']);

it('rejects stale eligibility and principal substitution during passwordless session establishment', function (bool $substitute): void {
    $user = $this->user();
    $other = $this->user('session-other@example.test');
    $context = $this->authenticationContext();
    $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    if ($substitute) {
        nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use ($other): Authenticatable {
            $next($context);

            return $other;
        });
    } else {
        $user->newQuery()->whereKey($user->id)->update(['is_active' => false]);
    }
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))
        ->toThrow(AuthException::class)
        ->and(auth()->guard('web')->check())->toBeFalse()
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(0);
})->with(['stale' => false, 'substitution' => true]);

it('rejects raw native token issuance for persisted inactive locked or deleted principals', function (string $state): void {
    $user = $this->user();
    match ($state) {
        'inactive' => $user->newQuery()->whereKey($user->id)->update(['is_active' => false]),
        'locked' => $user->newQuery()->whereKey($user->id)->update(['locked_until' => AuthInstantCast::forQuery($user->getConnection(), now()->addHour())]),
        'deleted' => $user->delete(),
    };
    expect(fn () => app(AuthTokens::class)->create($user, ['name' => 'Rejected device', 'abilities' => ['profile:read']]))
        ->toThrow(AuthException::class)
        ->and($user->tokens()->count())->toBe(0)
        ->and(AuthAudit::query()->where('action', 'api_token.issued')->count())->toBe(0);
})->with(['inactive', 'locked', 'deleted']);

it('invalidates pending native factor proof after password change and after the attempt budget', function (bool $passwordChanged): void {
    config(['nvl-auth.features.totp.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $login = app(Authentication::class);
    $guard = auth()->guard('web');
    $session = app('session.store');
    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class);
    if ($passwordChanged) {
        $user->forceFill(['password' => 'replacement-password'])->save();
    }
    for ($attempt = 0; $attempt < ($passwordChanged ? 1 : 5); $attempt++) {
        expect(fn () => $login->completeSecondFactor(['code' => 'invalid'], $guard, $session))->toThrow(AuthException::class);
    }
    expect($login->hasPendingSecondFactor($session))->toBeFalse()
        ->and($guard->check())->toBeFalse()
        ->and($user->fresh()->last_login_at)->toBeNull();
})->with(['password changed' => true, 'attempt budget' => false]);

it('preserves non Eloquent principal contracts for explicitly configured raw token adapters', function (): void {
    $principal = new GenericUser(['id' => 'directory-user']);
    $issued = new IssuedApiToken([
        'id' => 'external-token', 'name' => 'External', 'abilities' => ['profile:read'],
        'lastUsedAt' => null, 'expiresAt' => null, 'createdAt' => CarbonImmutable::now(),
    ], 'external-secret');
    $manager = Mockery::mock(ApiTokenManager::class);
    $manager->shouldReceive('create')->once()->with($principal, Mockery::type('array'))->andReturn($issued);
    app()->instance(ApiTokenManager::class, $manager);

    expect(app(AuthTokens::class)->create($principal, ['name' => 'External', 'abilities' => ['profile:read']]))->toBe($issued);
});

it('expires a native server session factor continuation before proof can establish a session', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $login = app(Authentication::class);
    $guard = auth()->guard('web');
    $session = app('session.store');
    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class);
    CarbonImmutable::setTestNow(CarbonImmutable::now()->addMinutes(6));
    try {
        expect($login->hasPendingSecondFactor($session))->toBeFalse()
            ->and(fn () => $login->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], $guard, $session))->toThrow(AuthException::class)
            ->and($guard->check())->toBeFalse()
            ->and($user->fresh()->last_login_at)->toBeNull();
    } finally {
        CarbonImmutable::setTestNow();
    }
});

it('preserves token containment for a canonical principal disabled after token issuance', function (): void {
    $user = $this->user();
    $tokens = app(AuthTokens::class);
    $tokens->create($user, ['name' => 'Revocable device', 'abilities' => ['profile:read']]);
    $user->newQuery()->whereKey($user->id)->update(['is_active' => false]);
    expect($tokens->revokeAll($user))->toBe(1)->and($user->tokens()->count())->toBe(0);
});

it('enforces native factor attempts and one use across stale session snapshots', function (bool $consume): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $login = app(Authentication::class);
    $guard = auth()->guard('web');
    $session = app('session.store');
    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class);
    $snapshot = $session->all();
    if ($consume) {
        $login->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], $guard, $session);
        $guard->logout();
    } else {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $session->replace($snapshot);
            expect(fn () => $login->completeSecondFactor(['code' => 'invalid'], $guard, $session))->toThrow(AuthException::class);
        }
    }
    $session->replace($snapshot);
    expect(fn () => $login->completeSecondFactor(['recoveryCode' => $recovery->codes[1]], $guard, $session))->toThrow(AuthException::class)
        ->and($guard->check())->toBeFalse()
        ->and($login->hasPendingSecondFactor($session))->toBeFalse();
    expect(app(AuthSecondFactor::class)->consumeRecoveryCode($user, ['code' => $recovery->codes[1]])->used_at)->not->toBeNull();
})->with(['consumed continuation' => true, 'attempt budget' => false]);

it('rejects skipped or repeated native login terminal calls', function (string $mode): void {
    $user = $this->user();
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use ($user, $mode): mixed {
        if ($mode === 'skip') {
            return $user;
        }
        $next($context);

        return $next($context);
    });
    expect(fn () => app(Authentication::class)->loginWithToken(['identifier' => $user->email, 'password' => 'correct-password'], ['name' => 'Rejected', 'abilities' => ['profile:read']]))->toThrow(AuthException::class);
    expect($user->tokens()->count())->toBe(0);
})->with(['skip', 'double']);

it('publishes native proof contracts and complete credential operations without internal issuance or bare establishment', function (): void {
    $catalog = json_decode(file_get_contents(__DIR__.'/../../resources/consumer-api.json'), true, flags: JSON_THROW_ON_ERROR)['symbols'];
    foreach ([PrincipalEmailIdentity::class, PrincipalEmailIdentityAdoption::class, Authentication::class, AuthenticationSessions::class, AuthenticationRequestContext::class, AuthenticationProofs::class, AuthenticationAssurancePolicy::class, AuthenticationMethod::class, AuthenticationDestination::class, AuthenticationEvidence::class, IssuedAuthenticationProof::class] as $symbol) {
        expect($catalog)->toHaveKey($symbol);
    }
    expect($catalog[PrincipalEmailIdentity::class]['methods'])->toContain('normalize', 'key')->not->toContain('credentials', 'brokerCredentials', 'assertReady', 'schemaReady', 'indexReady');
    expect($catalog[Authentication::class]['methods'])->toContain('login', 'loginWithToken', 'proveCredentials', 'proveCredentialsForToken')
        ->and($catalog[AuthenticationSessions::class]['methods'])->toContain('establishFromProof')->not->toContain('establish', 'establishForPurpose')
        ->and($catalog[Authentication::class]['methods'])->not->toContain('passwordProof', 'issueNativeProof')
        ->and($catalog[AuthenticationProofs::class]['methods'])->not->toContain('recheck', 'consumeForFinalization')
        ->and($catalog)->not->toHaveKeys([IssuesAuthenticationProofs::class, AuthenticationVerification::class])
        ->and((new ReflectionClass(AuthenticationEvidence::class))->hasProperty('passwordBinding'))->toBeFalse();
});

it('preserves the mapped password identifier in browser and token login pipeline contexts', function (string $destination): void {
    $user = $this->user();
    $user->forceFill(['name' => $user->email])->save();
    config(['nvl-auth.features.principal_management.settings.attributes.email' => 'name', 'nvl-auth.features.principal_management.settings.attributes.name' => 'email']);
    app()->forgetInstance(PrincipalAttributeMapper::class);
    $attributes = null;
    nativeStatelessStage(function (AuthPipelineContext $context, Closure $next) use (&$attributes): mixed {
        $attributes = $context->attributes;

        return $next($context);
    });
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    if ($destination === 'browser') {
        app(Authentication::class)->login($credentials, ['remember' => true], auth()->guard('web'), app('session.store'));
    } else {
        app(Authentication::class)->loginWithToken($credentials, ['name' => 'Mapped login', 'abilities' => ['profile:read']]);
    }
    expect($attributes)->toBe($destination === 'browser'
        ? ['method' => 'credential_login', 'remember' => true, 'identifier_name' => 'name']
        : ['method' => 'credential_login', 'stateless' => true, 'identifier_name' => 'name']);
})->with(['browser', 'token']);

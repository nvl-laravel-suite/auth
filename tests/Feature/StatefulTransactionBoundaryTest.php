<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public\SocialIdentityController;
use Nvl\Auth\Tests\Fixtures\TestUser;

it('rejects outer transactions before browser effects and permits retry after rollback', function (string $operation): void {
    $user = $this->user();
    $guard = auth()->guard('web');
    $session = app('session.store');
    $context = $this->authenticationContext();
    $login = app(Authentication::class);
    if ($operation === 'factor') {
        config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
        TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
        $recovery = RecoveryCode::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass(), 'code_hash' => app(SecretHasher::class)->hash('recovery-code', 'BOUNDARY-CODE')]);
        expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class, 'second factor');
        $call = fn () => $login->completeSecondFactor(['recoveryCode' => 'BOUNDARY-CODE'], $guard, $session);
    } elseif ($operation === 'proof') {
        $proof = $login->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
        $call = fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), $guard, $session, $context);
    } elseif ($operation === 'logout' || $operation === 'delete') {
        $guard->login($user);
        $context = $this->authenticationContext();
        if ($operation === 'delete') {
            $grant = $this->recentGrant($user, RecentAuthenticationPurpose::AccountDeletion);
            $call = fn () => app(AuthUsers::class)->deleteOwnAccount($user, [], $guard, $session, $grant->reveal(), $context);
        } else {
            $call = fn () => app(AuthenticationSessions::class)->logout($guard, $session);
        }
    } else {
        $session->put('nvl-auth.credential_login', ['previous' => 'retained']);
        $call = fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session);
    }
    $session->put('host-marker', 'untouched');
    $before = $session->all();
    $sessionId = $session->getId();
    $guardId = $guard->id();
    $proofs = Challenge::query()->get()->map->getAttributes()->all();
    DB::beginTransaction();
    try {
        expect($call)->toThrow(AuthException::class, 'transaction');
        expect($session->all())->toBe($before)->and($session->getId())->toBe($sessionId)->and($guard->id())->toBe($guardId)
            ->and(Challenge::query()->get()->map->getAttributes()->all())->toBe($proofs);
        if (isset($recovery)) {
            expect($recovery->refresh()->used_at)->toBeNull();
        }
    } finally {
        DB::rollBack();
    }
    $call();
    expect($guard->check())->toBe(! in_array($operation, ['logout', 'delete'], true));
})->with(['password', 'proof', 'factor', 'logout', 'delete']);

it('allows standalone persisted proof issuance inside a host transaction but never session establishment', function (): void {
    $user = $this->user();
    DB::beginTransaction();
    try {
        $context = $this->authenticationContext();
        $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
        expect(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(1);
        expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))->toThrow(AuthException::class, 'transaction');
    } finally {
        DB::rollBack();
    }
    expect(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(0)->and(auth()->guard('web')->check())->toBeFalse();
});

it('checks the configured provider source rather than only the default connection', function (): void {
    config(['database.connections.boundary_secondary' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    $model = new class extends User
    {
        protected $connection = 'boundary_secondary';
    };
    config(['auth.providers.users.model' => $model::class]);
    Event::fake([AuthenticationAttempted::class]);
    DB::connection('boundary_secondary')->beginTransaction();
    try {
        expect(DB::connection()->transactionLevel())->toBe(0);
        expect(fn () => app(Authentication::class)->login(['identifier' => 'unread@example.test', 'password' => 'unchanged'], [], auth()->guard('web'), app('session.store')))->toThrow(AuthException::class, 'transaction');
        Event::assertNotDispatched(AuthenticationAttempted::class);
    } finally {
        DB::connection('boundary_secondary')->rollBack();
    }
});

it('preflights the immediate social callback before pulling its session map or calling the SDK', function (): void {
    $session = app('session.store');
    $key = 'native-social.'.hash('sha256', 'github:state');
    $session->put($key, ['pending' => 'untouched']);
    $request = Request::create('/callback?state=state');
    $request->setLaravelSession($session);
    DB::beginTransaction();
    try {
        expect(fn () => app()->call([app(SocialIdentityController::class), 'callback'], ['provider' => 'github', 'request' => $request]))->toThrow(AuthException::class, 'transaction');
        expect($session->get($key))->toBe(['pending' => 'untouched']);
    } finally {
        DB::rollBack();
    }
});

it('cleans partial browser authentication and rotates CSRF after immediate transition failure', function (string $failure): void {
    $user = $this->user();
    $session = app('session.store');
    $session->put('host-marker', 'must-be-invalidated');
    $session->regenerateToken();
    $token = $session->token();
    $guard = auth()->guard('web');
    if ($failure === 'metadata') {
        $metadata = Mockery::mock(SuccessfulLoginMetadataRecorder::class);
        $metadata->shouldReceive('record')->once()->andThrow(new RuntimeException('metadata failed'));
        app()->instance(SuccessfulLoginMetadataRecorder::class, $metadata);
    } elseif (in_array($failure, ['session', 'session_false'], true)) {
        $session = Mockery::mock($session);
        if ($failure === 'session') {
            $session->shouldReceive('regenerate')->once()->with(true)->andThrow(new RuntimeException('session failed'));
        } else {
            $session->shouldReceive('regenerate')->once()->with(true)->andReturn(false);
        }
    } else {
        $actual = $guard;
        $guard = Mockery::mock($actual);
        $guard->shouldReceive('login')->once()->andReturnUsing(function ($subject, $remember) use ($actual): void {
            $actual->login($subject, $remember);
            throw new RuntimeException('guard failed');
        });
        auth()->extend('failing_guard', fn () => $guard);
        config(['auth.guards.web.driver' => 'failing_guard']);
        auth()->forgetGuards();
    }
    Event::fake([UserAuthenticated::class]);
    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(RuntimeException::class, 'failed');
    expect($guard->check())->toBeFalse()->and($session->get('host-marker'))->toBeNull()->and($session->token())->not->toBe($token)
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe(0)
        ->and($user->fresh()->last_login_at)->toBeNull();
    Event::assertNotDispatched(UserAuthenticated::class);
})->with(['metadata', 'session', 'session_false', 'guard']);

it('retains outer-aware domain creation with no publication after rollback', function (): void {
    $actor = $this->user();
    Event::fake([PrincipalChanged::class]);
    DB::beginTransaction();
    try {
        app(AuthUsers::class)->create($actor, ['name' => 'Rolled back', 'email' => 'rolled-back@example.test', 'password' => 'correct-password']);
        Event::assertNotDispatched(PrincipalChanged::class);
    } finally {
        DB::rollBack();
    }
    expect(TestUser::query()->where('email', 'rolled-back@example.test')->exists())->toBeFalse();
    Event::assertNotDispatched(PrincipalChanged::class);
});

it('preflights logout before guard resolution and checks the resolved subject source', function (string $source): void {
    $subject = $this->user();
    $guard = Mockery::mock(StatefulGuard::class);
    $session = Mockery::mock(Session::class);
    if ($source === 'subject') {
        config(['database.connections.logout_subject' => config('database.connections.'.config('database.default'))]);
        $subject->setConnection('logout_subject');
        $guard->shouldReceive('user')->once()->andReturn($subject);
    } else {
        $guard->shouldNotReceive('user');
    }
    $guard->shouldNotReceive('logout');
    $session->shouldNotReceive('invalidate');
    $connection = $subject->getConnection();
    $connection->beginTransaction();
    try {
        expect(fn () => app(AuthenticationSessions::class)->logout($guard, $session))->toThrow(AuthException::class, 'enclosing source transaction');
    } finally {
        $connection->rollBack();
    }
})->with(['common', 'subject']);

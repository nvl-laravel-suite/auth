<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Hashing\HashManager;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\AuthAuditContextProvider;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Events\UserLoggedOut;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Services\AuthAuditReader;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Tests\Fixtures\HostAuditRecorder;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;

it('logs in and out through the configured Laravel stateful guard', function (): void {
    $user = $this->user();
    Event::fake([
        AuthenticationAttempted::class,
        UserAuthenticated::class,
        UserLoggedOut::class,
    ]);
    $authenticated = app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], ['ipAddress' => '203.0.113.10'], auth()->guard('web'), app('session')->driver());

    expect($authenticated->getAuthIdentifier())->toBe($user->getAuthIdentifier())
        ->and(Auth::guard('web')->check())->toBeTrue()
        ->and($user->refresh()->last_login_ip)->toBe('203.0.113.10')
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->exists())->toBeTrue();

    app(AuthenticationSessions::class)->logout(auth()->guard('web'), app('session')->driver());

    expect(Auth::guard('web')->check())->toBeFalse();
    Event::assertDispatched(AuthenticationAttempted::class);
    Event::assertDispatched(UserAuthenticated::class);
    Event::assertDispatched(UserLoggedOut::class);
});

it('emits a transport-neutral rejection event and records through a host audit adapter', function (): void {
    $recorder = new HostAuditRecorder;
    $this->app->instance(Nvl\Auth\Contracts\AuthAuditRecorder::class, $recorder);
    Event::fake([AuthenticationAttempted::class, AuthenticationRejected::class]);

    expect(fn () => app(Authentication::class)->login(['identifier' => 'missing@example.test', 'password' => 'wrong-password'], [], auth()->guard('web'), app('session')->driver()))
        ->toThrow(AuthException::class, 'invalid');

    expect($recorder->facts)->toHaveCount(1)
        ->and($recorder->facts[0]['action'])->toBe('authentication.failed');

    Event::assertDispatched(AuthenticationAttempted::class);
    Event::assertDispatched(
        AuthenticationRejected::class,
        static fn (AuthenticationRejected $event): bool => $event->reason === 'credentials_invalid'
            && $event->identifier === 'missing@example.test',
    );
});

it('spends one password hash and fails identically for unknown, passwordless and wrong-password logins', function (): void {
    $this->user('known@example.test');
    $this->user('passwordless@example.test')->update(['password' => null]);
    $hasher = new class($this->app) extends HashManager
    {
        public int $operations = 0;

        public function make(#[SensitiveParameter] $value, array $options = [])
        {
            $this->operations++;

            return parent::make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = [])
        {
            $this->operations++;

            return parent::check($value, $hashedValue, $options);
        }
    };
    Hash::swap($hasher);
    $attempt = function (string $identifier) use ($hasher): array {
        $hasher->operations = 0;
        try {
            app(Authentication::class)->login(['identifier' => $identifier, 'password' => 'wrong-password'], [], auth()->guard('web'), app('session')->driver());
        } catch (Throwable $exception) {
            return [
                'exception' => $exception::class,
                'code' => $exception instanceof AuthException ? $exception->errorCode : null,
                'status' => $exception instanceof AuthException ? $exception->status : null,
                'message' => $exception->getMessage(),
                'hashes' => $hasher->operations,
            ];
        }

        return [];
    };

    $wrongPassword = $attempt('known@example.test');

    expect($wrongPassword)->toMatchArray(['exception' => AuthException::class, 'code' => 'credentials_invalid', 'status' => 422, 'hashes' => 1])
        ->and($attempt('missing@example.test'))->toBe($wrongPassword)
        ->and($attempt('passwordless@example.test'))->toBe($wrongPassword);
    $audits = AuthAudit::query()->get()->map(fn (AuthAudit $audit): array => [$audit->action, $audit->outcome, $audit->subject_id, $audit->metadata]);
    expect($audits)->toHaveCount(3)
        ->and($audits->unique()->all())->toBe([['authentication.failed', 'failure', null, ['reason' => 'credentials_invalid']]]);
});

it('bounds untrusted audit request context', function (): void {
    $this->app->instance(AuthAuditContextProvider::class, new class implements AuthAuditContextProvider
    {
        public function ipAddress(): ?string
        {
            return str_repeat('1', 100);
        }

        public function userAgent(): ?string
        {
            return str_repeat('u', 2_000);
        }

        public function requestId(): ?string
        {
            return str_repeat('r', 200);
        }
    });

    $audit = app(AuthAuditRecorder::class)->record('context.test');

    expect($audit)->not->toBeNull()
        ->and(strlen((string) $audit?->ip_address))->toBe(64)
        ->and(strlen((string) $audit?->user_agent))->toBe(1_024)
        ->and(strlen((string) $audit?->request_id))->toBe(128);
});

it('confirms the current password through Laravel session authority', function (): void {
    $user = $this->user();
    $request = app('request');
    $request->setLaravelSession(app('session')->driver());

    expect(fn () => app(AuthPasswords::class)->confirm($user, ['password' => 'wrong-password'], app('session')->driver()))
        ->toThrow(AuthException::class, 'invalid');

    app(AuthPasswords::class)->confirm($user, ['password' => 'correct-password'], app('session')->driver());

    expect($request->session()->get('auth.password_confirmed_at'))->toBeInt()
        ->and(AuthAudit::query()->where('action', 'password.confirmed')->exists())->toBeTrue();
});

it('runs the login pipeline after credential resolution and logs out rejected subjects', function (): void {
    $user = $this->user();
    RejectLoginStage::$subject = null;
    config()->set('nvl-auth.pipelines.login', [RejectLoginStage::class]);

    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session')->driver()))
        ->toThrow(AuthException::class, 'rejected');

    expect(RejectLoginStage::$subject?->identifier)->toBe((string) $user->getKey())
        ->and(Auth::guard('web')->check())->toBeFalse()
        ->and($user->refresh()->last_login_at)->toBeNull();
});

it('applies shared eligibility and rejection semantics to passwordless sessions', function (): void {
    $user = $this->user();
    $context = $this->authenticationContext();
    config(['nvl-auth.features.magic_links.enabled' => true]);
    $challenges = app(AuthChallenges::class);
    $issued = $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
    $proof = $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $issued['secret']], $context);
    $user->forceFill(['is_active' => false])->save();
    Event::fake([AuthenticationRejected::class]);

    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session')->driver(), $context))->toThrow(AuthException::class, 'cannot be completed');

    expect(Auth::guard('web')->check())->toBeFalse()
        ->and($user->refresh()->last_login_at)->toBeNull()
        ->and(AuthAudit::query()->where('action', 'authentication.rejected')->exists())->toBeTrue();
    Event::assertDispatched(AuthenticationRejected::class);
});

it('authorizes audit detail access with decrypted metadata', function (): void {
    $user = $this->user();
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session')->driver());
    $audit = AuthAudit::query()->where('action', 'authentication.succeeded')->sole();

    expect(app(AuthAuditReader::class)->find($user, $audit)->is($audit))->toBeTrue()
        ->and($audit->metadata)->toBeArray();
});

it('runs each Auth schema catalog probe once per password login', function (bool $managed): void {
    config(['nvl-auth.features.managed_sessions.enabled' => $managed]);
    $user = $this->user('catalog-probes@example.test');
    $probes = [];
    DB::listen(static function (QueryExecuted $query) use (&$probes): void {
        $statement = $query->sql.' '.json_encode($query->bindings);
        // Core's ownership marker probe belongs to another package and is not counted here.
        if (preg_match('/sqlite_master|pragma_|information_schema|pg_catalog|pg_class|pg_index|pg_attribute/i', $statement) === 1 && ! str_contains($statement, 'nvl_ownership_resource_markers')) {
            $probes[] = $statement;
        }
    });
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store'));

    expect(Auth::guard('web')->check())->toBeTrue()
        ->and($probes)->not->toBeEmpty()
        ->and(array_keys(array_filter(array_count_values($probes), static fn (int $count): bool => $count > 1)))->toBe([]);
})->with(['Laravel sessions' => [false], 'managed sessions' => [true]]);

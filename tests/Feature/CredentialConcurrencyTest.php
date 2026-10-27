<?php

declare(strict_types=1);
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\SecurityTokenContainment;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Tests\Fixtures\SecurityRace;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\SubjectReference;

beforeEach(function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $requested = getenv('NVL_C1_TEST_DRIVER');
    if (in_array($requested, ['mysql', 'pgsql'], true)) {
        expect(DB::connection()->getDriverName())->toBe($requested);
    }
});
it('retains monotonic security revision and rolls back credential replacement', function (): void {
    $user = $this->user();
    $security = app(PrincipalSecurity::class);
    expect($security->revision($user))->toBe(1);
    $batch = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    expect($security->revision($user))->toBe(2);
    try {
        $grant = $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration);
        DB::transaction(function () use ($user, $grant): void {
            app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $grant->reveal(), context: $this->authenticationContext());
            throw new RuntimeException('host rollback');
        });
    } catch (RuntimeException $exception) {
        expect($exception->getMessage())->toBe('host rollback');
    }
    expect($security->revision($user))->toBe(2)
        ->and(RecoveryCode::query()->whereNull('revoked_at')->pluck('batch_id')->unique()->all())->toBe([$batch->batchId]);
});
it('creates one initial security state from two committed processes', function (): void {
    $id = $this->user()->getKey();
    $worker = static fn (): array => ['revision' => app(PrincipalSecurity::class)->revision(TestUser::query()->findOrFail($id))];
    $results = SecurityRace::run([$worker, $worker]);
    expect(array_column($results, 'ok'))->toBe([true, true], json_encode($results, JSON_THROW_ON_ERROR))
        ->and(array_column($results, 'revision'))->toBe([1, 1])
        ->and(PrincipalSecurityState::query()->count())->toBe(1);
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires MySQL/PostgreSQL.');
it('serializes concurrent credential inventory replacements', function (string $operation): void {
    $user = $this->user();
    $id = $user->getKey();
    $purpose = $operation === 'totp' ? RecentAuthenticationPurpose::FactorEnrollment : RecentAuthenticationPurpose::RecoveryRegeneration;
    $firstGrant = $this->recentGrant($user, $purpose)->reveal();
    $secondGrant = $this->recentGrant($user, $purpose)->reveal();
    $context = $this->authenticationContext();
    $worker = static function (string $grant) use ($id, $operation, $context): array {
        DB::listen(static function ($query) use ($operation): void {
            if (str_starts_with(strtolower($query->sql), $operation === 'totp' ? 'delete' : 'update')) {
                usleep(250000);
            }
        });
        $user = TestUser::query()->findOrFail($id);
        if ($operation === 'totp') {
            app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email], grant: $grant, context: $context);
        } else {
            app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $grant, context: $context);
        }

        return [];
    };
    $results = SecurityRace::run([static fn (): array => $worker($firstGrant), static fn (): array => $worker($secondGrant)]);
    expect(count(array_filter(array_column($results, 'ok'))))->toBe(1, json_encode($results, JSON_THROW_ON_ERROR));
    if ($operation === 'totp') {
        expect(TotpCredential::query()->whereNull('confirmed_at')->whereNull('revoked_at')->count())->toBe(1);
    } else {
        expect(RecoveryCode::query()->whereNull('revoked_at')->distinct()->count('batch_id'))->toBe(1);
    }
})->with(['totp', 'recovery'])->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires MySQL/PostgreSQL.');

it('finishes passkey verification outside the security transaction', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony(beforeRegistration: static function (): void {
        expect(DB::connection()->transactionLevel())->toBe(0);
    }));
    $user = $this->user();
    $service = app(AuthPasskeys::class);
    $options = $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $service->finishRegistration($user, ['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
});

it('never exceeds the passkey limit when distinct ceremonies finish together', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true, 'nvl-auth.features.passkeys.settings.max_credentials_per_subject' => 1]);
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony(beforeRegistration: static function (): void {
        usleep(250000);
    }));
    $user = $this->user();
    $id = $user->getKey();
    $service = app(AuthPasskeys::class);
    $options = [$service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()), $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext())];
    $workers = [];
    $context = $this->authenticationContext();
    foreach ($options as $index => $option) {
        $workers[] = static function () use ($id, $index, $option, $context): array {
            try {
                app(AuthPasskeys::class)->finishRegistration(TestUser::query()->findOrFail($id), ['ceremonyId' => $option->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'race-'.$index]], grant: app(AuthReauthentication::class)->confirm(TestUser::query()->findOrFail($id), ['password' => 'correct-password'], RecentAuthenticationPurpose::FactorEnrollment, $context)->reveal(), context: $context);

                return ['enrolled' => true];
            } catch (AuthException $exception) {
                return ['enrolled' => false, 'rejection' => $exception->errorCode];
            }
        };
    }
    $results = SecurityRace::run($workers);
    expect(array_column($results, 'ok'))->toBe([true, true], json_encode($results, JSON_THROW_ON_ERROR))
        ->and(array_sum(array_column($results, 'enrolled')))->toBe(1)
        ->and(Passkey::query()->whereNull('revoked_at')->count())->toBe(1);
})->skip(fn (): bool => DB::connection()->getDriverName() === 'sqlite', 'Committed process race requires MySQL/PostgreSQL.');

it('advances passwords and revokes only exact managed token namespaces', function (): void {
    config(['nvl-auth.features.api_tokens.settings.namespace' => 'secure_auth']);
    $user = $this->user();
    $managed = $user->createToken('secure_auth:managed');
    $unrelated = $user->createToken('secureXauth:unrelated');
    $differentCase = $user->createToken('SECURE_AUTH:unrelated');
    app(AuthPasswords::class)->update($user, ['password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123'], grant: $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange, 'correct-password')->reveal(), context: $this->authenticationContext());
    expect(app(PrincipalSecurity::class)->revision($user))->toBe(2)
        ->and($managed->accessToken->fresh())->toBeNull()
        ->and($unrelated->accessToken->fresh())->not->toBeNull()
        ->and($differentCase->accessToken->fresh())->not->toBeNull();
});

it('retains security revision through disable delete and restore without profile increments', function (): void {
    $actor = $this->user('actor@example.test');
    $user = $this->user();
    $users = app(AuthUsers::class);
    $security = app(PrincipalSecurity::class);
    expect($security->revision($user))->toBe(1);
    $users->update($actor, $user, ['name' => 'New name']);
    expect($security->revision($user))->toBe(1);
    $users->setActive($actor, $user, ['active' => false]);
    expect($security->revision($user))->toBe(2);
    $users->setActive($actor, $user, ['active' => false]);
    expect($security->revision($user))->toBe(2);
    $users->delete($actor, $user);
    expect($security->revision($user))->toBe(3);
    $users->restore($actor, $user);
    expect($security->revision($user))->toBe(4);
});

it('leaves committed facts and revisions untouched after password rollback', function (): void {
    $user = $this->user();
    $security = app(PrincipalSecurity::class);
    expect($security->revision($user))->toBe(1);
    $token = $user->createToken('nvl-auth:managed');
    try {
        $grant = $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange);
        DB::transaction(function () use ($user, $grant): void {
            app(AuthPasswords::class)->update($user, ['password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123'], grant: $grant->reveal(), context: $this->authenticationContext());
            throw new RuntimeException('rollback password');
        });
    } catch (RuntimeException $exception) {
        expect($exception->getMessage())->toBe('rollback password');
    }
    expect($security->revision($user))->toBe(1)
        ->and(Hash::check('correct-password', $user->refresh()->password))->toBeTrue()
        ->and($token->accessToken->fresh())->not->toBeNull()
        ->and(AuthAudit::query()->where('action', 'password.updated')->count())->toBe(0);
});

it('rejects a mismatched token source before writing credentials or security state', function (): void {
    $user = $this->user();
    config(['database.connections.security_elsewhere' => config('database.connections.'.config('database.default'))]);
    $tokens = Mockery::mock(SecurityTokenContainment::class);
    $tokens->shouldReceive('connection')->andReturn(DB::connection('security_elsewhere'));
    app()->instance(ApiTokenManager::class, $tokens);
    expect(fn () => app(AuthPasswords::class)->update($user, ['password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123'], grant: $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange, 'correct-password')->reveal(), context: $this->authenticationContext()))
        ->toThrow(AuthException::class, 'actual principal source');
    expect(PrincipalSecurityState::query()->count())->toBe(0)
        ->and(Hash::check('correct-password', $user->refresh()->password))->toBeTrue();
});

it('changes passwords when optional API tokens are disabled', function (): void {
    config(['nvl-auth.features.api_tokens.enabled' => false]);
    $user = $this->user();
    app(AuthPasswords::class)->update($user, ['password' => 'new-password-123', 'passwordConfirmation' => 'new-password-123'], grant: $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange, 'correct-password')->reveal(), context: $this->authenticationContext());
    expect(app(PrincipalSecurity::class)->revision($user))->toBe(2);
});

it('rejects unknown revision reasons without mutating the store', function (): void {
    $user = $this->user();
    expect(fn () => DB::transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'caller_supplied')))->toThrow(InvalidArgumentException::class);
    expect(PrincipalSecurityState::query()->count())->toBe(0);
});

it('advances administrative email and activation mutations', function (array $data): void {
    $actor = $this->user('actor@example.test');
    $user = $this->user();
    if (array_key_exists('active', $data)) {
        app(AuthUsers::class)->setActive($actor, $user, $data);
    } else {
        app(AuthUsers::class)->update($actor, $user, $data);
    }
    expect(app(PrincipalSecurity::class)->revision($user))->toBe(2);
})->with([[['active' => false]], [['email' => 'changed@example.test']]]);

it('verifies passkey assertions outside principal and challenge locks', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony(beforeAuthentication: static function (): void {
        expect(DB::connection()->transactionLevel())->toBe(0);
    }));
    $user = $this->user();
    $service = app(AuthPasskeys::class);
    $options = $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $service->finishRegistration($user, ['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $options = $service->beginAuthentication($user, context: $this->authenticationContext());
    $service->finishAuthentication(['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId());
});

it('invalidates native authentication challenges while preserving business challenges', function (): void {
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $native = Challenge::factory()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'type' => 'credential_second_factor']);
    $business = Challenge::factory()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'type' => 'security_code', 'purpose' => 'approve_invoice']);
    app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    expect($native->refresh()->revoked_at)->not->toBeNull()->and($business->refresh()->revoked_at)->toBeNull();
});

it('locks the social callback principal before its credential', function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    $user = $this->user();
    $external = new ExternalIdentity('github', 'callback-order');
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: $external)));
    $service = app(AuthSocialIdentities::class);
    $service->link($user, $external, grant: $this->recentGrant($user, RecentAuthenticationPurpose::SocialLink, 'correct-password')->reveal(), context: $this->authenticationContext());
    $queries = [];
    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        if ($query->connection->transactionLevel() > 0 && str_starts_with(strtolower($query->sql), 'select') && (str_contains($query->sql, 'nvl_auth_users') || str_contains($query->sql, 'nvl_auth_social_identities'))) {
            $queries[] = $query->sql;
        }
    });
    $this->completeSocialAuthentication($service, 'github');
    expect($queries[0])->toContain('nvl_auth_users')
        ->and(app(PrincipalSecurity::class)->revision($user))->toBe(2);
});

it('locks the factor continuation principal before its challenge', function (): void {
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $login = app(Authentication::class);
    $session = app('session.store');
    $session->start();
    $guard = auth()->guard('web');
    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class, 'second factor');
    $queries = [];
    DB::listen(function (QueryExecuted $query) use (&$queries): void {
        if ($query->connection->transactionLevel() > 0 && str_starts_with(strtolower($query->sql), 'select') && (str_contains($query->sql, 'nvl_auth_users') || str_contains($query->sql, 'nvl_auth_challenges'))) {
            $queries[] = $query->sql;
        }
    });
    $login->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], $guard, $session);
    expect($queries[0])->toContain('nvl_auth_users')->and($guard->id())->toBe($user->id);
});

it('rejects a passkey resolver that returns a different canonical principal', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony);
    $user = $this->user();
    $other = $this->user('other@example.test');
    $service = app(AuthPasskeys::class);
    $registration = $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $service->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $options = $service->beginAuthentication($user, context: $this->authenticationContext());
    $resolver = Mockery::mock(AuthSubjectResolver::class);
    $resolver->shouldReceive('resolve')->andReturn($other);
    app()->instance(AuthSubjectResolver::class, $resolver);
    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class);
});

it('enforces one persisted security state per canonical subject', function (): void {
    $user = $this->user();
    app(PrincipalSecurity::class)->revision($user);
    $state = PrincipalSecurityState::query()->sole();
    expect(fn () => PrincipalSecurityState::query()->create(['subject_type' => $state->subject_type, 'subject_id' => $state->subject_id, 'revision' => 1]))
        ->toThrow(UniqueConstraintViolationException::class);
    expect(PrincipalSecurityState::query()->count())->toBe(1);
});

it('takes a read-only passkey snapshot before provider verification inside a host transaction', function (bool $hasState): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    $observed = [];
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony(beforeAuthentication: static function () use (&$observed): void {
        $observed = ['queries' => DB::connection()->getQueryLog(), 'level' => DB::connection()->transactionLevel(), 'states' => PrincipalSecurityState::query()->count()];
    }));
    $user = $this->user();
    $service = app(AuthPasskeys::class);
    $registration = $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $passkey = $service->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    if (! $hasState) {
        PrincipalSecurityState::query()->delete();
    }
    $authentication = $service->beginAuthentication($user, context: $this->authenticationContext());
    DB::beginTransaction();
    try {
        DB::connection()->flushQueryLog();
        DB::connection()->enableQueryLog();
        $result = $service->finishAuthentication(['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId());
        expect($result['subject']->identifier)->toBe((string) $user->getKey())
            ->and(DB::connection()->transactionLevel())->toBe(1)
            ->and($passkey->refresh()->signature_counter)->toBe(2);
    } finally {
        DB::connection()->disableQueryLog();
        DB::rollBack();
    }
    expect($observed['level'])->toBe(1)
        ->and($observed['states'])->toBe($hasState ? 1 : 0)
        ->and(array_filter($observed['queries'], static fn (array $query): bool => preg_match('/\b(for update|insert|update|delete|savepoint)\b/i', $query['query']) === 1))->toBe([])
        ->and($passkey->refresh()->signature_counter)->toBe(1)
        ->and(PrincipalSecurityState::query()->count())->toBe($hasState ? 1 : 0)
        ->and(Challenge::query()->where('type', 'passkey_authentication')->sole()->consumed_at)->toBeNull();
})->with(['retained state' => true, 'uninitialized state' => false]);

it('rejects passkey revision or credential drift after provider verification in a host transaction', function (string $drift): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    app()->instance(PasskeyCeremony::class, new TestPasskeyCeremony(beforeAuthentication: static function () use ($drift): void {
        if ($drift === 'revision') {
            PrincipalSecurityState::query()->increment('revision');
        } else {
            Passkey::query()->sole()->forceFill(['public_key' => 'changed-during-verification'])->save();
        }
    }));
    $user = $this->user();
    $service = app(AuthPasskeys::class);
    $registration = $service->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $passkey = $service->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $authentication = $service->beginAuthentication($user, context: $this->authenticationContext());
    DB::beginTransaction();
    try {
        expect(fn () => $service->finishAuthentication(['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class, 'unavailable');
        expect($passkey->refresh()->signature_counter)->toBe(1)
            ->and(Challenge::query()->where('type', 'passkey_authentication')->sole()->consumed_at)->toBeNull();
    } finally {
        DB::rollBack();
    }
})->with(['revision', 'credential']);

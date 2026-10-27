<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationProofs;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthSchemaManager;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\OwnerAuthenticationIntents;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Tests\Fixtures\ConfiguredOwnerUser;
use Nvl\Auth\Tests\Fixtures\Consumer\Http\Controllers\Public\SocialIdentityController;
use Nvl\Auth\Tests\Fixtures\HostAuditRecorder;
use Nvl\Auth\Tests\Fixtures\RejectLoginStage;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\Tests\Fixtures\TestSocialSubjectResolver;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAvailability;
use Nvl\Ownership\Contracts\OwnershipActorResolver;
use Nvl\Ownership\Services\ExistingOwnerAvailability;
use Nvl\Ownership\Services\NativeOwnershipActorResolver;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

it('binds a native password proof to its browser and consumes it only once', function (): void {
    $user = $this->user();
    $session = app('session.store');
    $session->start();
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $session->getId());
    $issued = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    $guard = auth()->guard('web');
    $sessions = app(AuthenticationSessions::class);
    expect($guard->check())->toBeFalse();
    expect(fn () => $sessions->establishFromProof($issued->reveal(), $guard, $session, new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'other-session')))->toThrow(AuthException::class);
    config(['auth.guards.other' => ['driver' => 'session', 'provider' => 'users']]);
    expect(fn () => $sessions->establishFromProof($issued->reveal(), auth()->guard('other'), $session, new AuthenticationRequestContext(guardName: 'other', sessionBinding: $session->getId())))->toThrow(AuthException::class);
    expect($sessions->establishFromProof($issued->reveal(), $guard, $session, $context)->getAuthIdentifier())->toBe($user->id);
    $guard->logout();
    expect(fn () => $sessions->establishFromProof($issued->reveal(), $guard, $session, $context))->toThrow(AuthException::class);
});

it('rejects proofs at the exact five minute expiry and after security changes', function (string $change): void {
    $user = $this->user();
    $session = app('session.store');
    $session->start();
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $session->getId());
    $this->freezeSecond();
    $issued = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    if ($change === 'expiry') {
        $this->travel(300)->seconds();
    } elseif ($change === 'revision') {
        $user->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'security_containment'));
    } else {
        $user->forceFill(['password' => 'changed-password'])->save();
    }
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($issued->reveal(), auth()->guard('web'), $session, $context))->toThrow(AuthException::class);
})->with(['expiry', 'revision', 'password']);

it('isolates token proof destinations and client flow namespaces without browser mutation', function (): void {
    $user = $this->user();
    $context = new AuthenticationRequestContext(tokenNamespace: 'mobile', flowNonce: str_repeat('a', 64));
    $credentials = ['identifier' => $user->email, 'password' => 'correct-password'];
    $token = ['name' => 'Native', 'abilities' => ['profile:read']];
    $issued = app(Authentication::class)->proveCredentialsForToken($credentials, $context);
    $session = app('session.store');
    $before = $session->all();
    $beforeId = $session->getId();
    $tokens = app(AuthTokens::class);
    expect(fn () => $tokens->authenticateFromProof($issued->reveal(), $token, new AuthenticationRequestContext(tokenNamespace: 'other', flowNonce: str_repeat('a', 64))))->toThrow(AuthException::class);
    expect(fn () => $tokens->authenticateFromProof($issued->reveal(), $token, new AuthenticationRequestContext(tokenNamespace: 'mobile', flowNonce: str_repeat('b', 64))))->toThrow(AuthException::class);
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($issued->reveal(), auth()->guard('web'), $session, $this->authenticationContext()))->toThrow(AuthException::class);
    expect($tokens->authenticateFromProof($issued->reveal(), $token, $context)['subject']->getAuthIdentifier())->toBe($user->id);
    expect(fn () => $tokens->authenticateFromProof($issued->reveal(), $token, $context))->toThrow(AuthException::class);
    expect($session->getId())->toBe($beforeId)->and($session->all())->toBe($before);
    $browserProof = app(Authentication::class)->proveCredentials($credentials, $this->authenticationContext());
    expect(fn () => $tokens->authenticateFromProof($browserProof->reveal(), $token, $context))->toThrow(AuthException::class);
});

it('does not promote generic or stale native email capabilities into authentication', function (): void {
    config(['nvl-auth.features.magic_links.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $generic = $challenges->requestMagicLink(['recipient' => $user->email], SubjectReference::fromAuthenticatable($user), ['verified' => true, 'method' => 'password', 'factors' => ['totp']]);
    expect(fn () => $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $generic['secret']], $context))->toThrow(AuthException::class);
    expect($challenges->consumeMagicLink(['recipient' => $user->email, 'token' => $generic['secret']])->consumed_at)->not->toBeNull();
    $native = $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
    $user->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'password_changed'));
    expect(fn () => $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $native['secret']], $context))->toThrow(AuthException::class);
});

it('preserves token proof consumption in an enclosing host rollback', function (): void {
    $user = $this->user();
    $context = new AuthenticationRequestContext(tokenNamespace: 'rollback', flowNonce: str_repeat('a', 64));
    $proof = app(Authentication::class)->proveCredentialsForToken(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    $token = ['name' => 'Atomic', 'abilities' => ['profile:read']];
    try {
        $user->getConnection()->transaction(function () use ($proof, $token, $context): void {
            app(AuthTokens::class)->authenticateFromProof($proof->reveal(), $token, $context);
            throw new RuntimeException('Host rollback');
        });
    } catch (RuntimeException $exception) {
        expect($exception->getMessage())->toBe('Host rollback');
    }
    expect($user->tokens()->count())->toBe(0);
    expect(app(AuthTokens::class)->authenticateFromProof($proof->reveal(), $token, $context)['subject']->getAuthIdentifier())->toBe($user->id);
});

it('spends one shared five-attempt factor budget and expires continuations exactly at 300 seconds', function (string $mode): void {
    config(['nvl-auth.features.totp.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $session = app('session.store');
    $guard = auth()->guard('web');
    $login = app(Authentication::class);
    $this->freezeSecond();
    expect(fn () => $login->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class, 'second factor');
    if ($mode === 'expiry') {
        $this->travel(300)->seconds();
        expect(fn () => $login->completeSecondFactor(['code' => 'invalid'], $guard, $session))->toThrow(AuthException::class);
    } else {
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            expect(fn () => $login->completeSecondFactor($attempt % 2 === 0 ? ['recoveryCode' => 'invalid'] : ['code' => 'invalid'], $guard, $session))->toThrow(AuthException::class);
        }
        expect(Challenge::query()->where('type', 'authentication_proof')->sole()->attempts)->toBe(5);
    }
    expect($login->hasPendingSecondFactor($session))->toBeFalse()->and($guard->check())->toBeFalse();
})->with(['attempts', 'expiry']);

it('does not disclose issued proof secrets through serialization or debugging', function (): void {
    $user = $this->user();
    $issued = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $this->authenticationContext());
    ob_start();
    var_dump($issued);
    $debug = ob_get_clean();
    expect($debug)->not->toContain($issued->reveal());
    expect(fn () => json_encode($issued, JSON_THROW_ON_ERROR))->toThrow(LogicException::class);
    expect(fn () => serialize($issued))->toThrow(LogicException::class);
});

it('installs mandatory proof storage with all optional delivery and factor methods disabled', function (): void {
    $schema = Schema::connection((new Challenge)->getConnectionName());
    $schema->drop(Challenge::TABLE);
    config(['nvl-auth.migrations.install_all' => false, 'nvl-auth.features.magic_links.enabled' => false, 'nvl-auth.features.security_codes.enabled' => false, 'nvl-auth.features.totp.enabled' => false]);
    $manager = app(AuthSchemaManager::class);
    expect($manager->requiredTables())->toContain(Challenge::TABLE);
    $manager->execute(true);
    expect($schema->hasColumns(Challenge::TABLE, ['secret_hash', 'secondary_secret_hash', 'payload', 'expires_at']))->toBeTrue();
});

it('rechecks canonical persistence even when a consumer resolver returns a stale principal', function (string $change): void {
    $user = $this->user();
    $context = $this->authenticationContext();
    $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    $this->app->instance(AuthSubjectResolver::class, new class($user) implements AuthSubjectResolver
    {
        public function __construct(private Authenticatable $subject) {}

        public function resolve(SubjectReference $reference): ?Authenticatable
        {
            return $this->subject;
        }
    });
    if ($change === 'password') {
        $user->newQuery()->whereKey($user->id)->update(['password' => password_hash('replacement-password', PASSWORD_BCRYPT, ['cost' => 4])]);
    } else {
        $user->newQuery()->whereKey($user->id)->update(['is_active' => false]);
    }
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))->toThrow(AuthException::class);
    expect(auth()->guard('web')->check())->toBeFalse();
})->with(['password', 'inactive']);

it('consumes a verified recovery capability before a later rejecting login pipeline', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $consumedBefore = Challenge::query()->where('type', 'authentication_proof')->whereNotNull('consumed_at')->count();
    $context = $this->authenticationContext();
    $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    app(AuthenticationProofs::class)->completeFactor($proof->reveal(), AuthenticationDestination::Session, $context, ['recoveryCode' => $recovery->codes[0]]);
    config(['nvl-auth.pipelines.login' => [RejectLoginStage::class]]);
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))->toThrow(AuthException::class, 'rejected');
    config(['nvl-auth.pipelines.login' => []]);
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))->toThrow(AuthException::class);
    expect(RecoveryCode::query()->whereNotNull('used_at')->count())->toBe(1)
        ->and(Challenge::query()->where('type', 'authentication_proof')->whereNotNull('consumed_at')->count())->toBe($consumedBefore + 1);
});

it('rejects another browser before redeeming native email and passkey primaries', function (string $method): void {
    config(['nvl-auth.features.magic_links.enabled' => true, 'nvl-auth.features.security_codes.enabled' => true, 'nvl-auth.features.passkeys.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $wrong = new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'another-browser');
    $challenges = app(AuthChallenges::class);
    if ($method === 'email_link') {
        $issued = $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
        $input = ['recipient' => $user->email, 'token' => $issued['secret']];
        expect(fn () => $challenges->consumeMagicLinkAuthentication($input, $wrong))->toThrow(AuthException::class);
        expect($challenges->consumeMagicLinkAuthentication($input, $context)->reveal())->not->toBeEmpty();
    } elseif ($method === 'email_code') {
        $issued = $challenges->requestSecurityCodeAuthentication(['recipient' => $user->email, 'purpose' => 'passwordless_login'], $context);
        $input = ['recipient' => $user->email, 'purpose' => 'passwordless_login', 'code' => $issued['secret']];
        expect(fn () => $challenges->proveSecurityCodeAuthentication($input, $wrong))->toThrow(AuthException::class);
        expect($challenges->proveSecurityCodeAuthentication($input, $context)->reveal())->not->toBeEmpty();
    } else {
        $this->app->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
        $passkeys = app(AuthPasskeys::class);
        $registration = $passkeys->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
        $passkeys->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
        $options = $passkeys->beginAuthentication(context: $context);
        $input = ['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]];
        expect(fn () => $passkeys->finishAuthentication($input, sessionBinding: $wrong->sessionBinding))->toThrow(AuthException::class);
        expect($passkeys->finishAuthentication($input, sessionBinding: $context->sessionBinding)['proof']->reveal())->not->toBeEmpty();
    }
})->with(['email_link', 'email_code', 'passkey']);

it('calls the social provider before native intent consumption inside an outer source transaction', function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    $user = $this->user();
    $this->app->instance(SocialSubjectResolver::class, new TestSocialSubjectResolver($user));
    $provider = new class implements SocialIdentityProvider
    {
        public bool $unconsumed = false;

        public function redirectUrl(string $provider, ?string $callbackUrl, array $scopes, array $parameters): string
        {
            return 'https://provider.example/authorize';
        }

        public function user(string $provider, ?string $callbackUrl): ExternalIdentity
        {
            $this->unconsumed = Challenge::query()->where('type', 'social_authentication')->sole()->consumed_at === null;

            return new ExternalIdentity($provider, 'social-user', email: 'claim@example.test', emailVerified: true, emailVerificationSource: 'fixture');
        }
    };
    $this->app->instance(SocialIdentityProviderFactory::class, new class($provider) implements SocialIdentityProviderFactory
    {
        public function __construct(private SocialIdentityProvider $provider) {}

        public function make(string $provider): SocialIdentityProvider
        {
            return $this->provider;
        }
    });
    $social = app(AuthSocialIdentities::class);
    $context = $this->authenticationContext();
    $intent = $social->startAuthentication('github', $context);
    $user->getConnection()->transaction(fn () => $social->finishAuthentication('github', $intent['intent']->reveal(), $context));
    expect($provider->unconsumed)->toBeTrue();
});

it('cannot stamp an earlier password verification with a later security revision', function (): void {
    $user = $this->user();
    $hasher = new class($user) extends BcryptHasher
    {
        public function __construct(private TestUser $principal)
        {
            parent::__construct(['rounds' => 4]);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = []): bool
        {
            $verified = parent::check($value, $hashedValue, $options);
            $this->principal->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($this->principal, 'totp_enrolled'));

            return $verified;
        }
    };
    $this->app->instance('hash', $hasher);
    expect(fn () => app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $this->authenticationContext()))->toThrow(AuthException::class);
    expect(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(0);
});

it('repairs retained challenge storage without deleting business capabilities and honors host-owned DDL', function (): void {
    config(['nvl-auth.features.magic_links.enabled' => true]);
    $issued = app(AuthChallenges::class)->requestMagicLink(['recipient' => 'business@example.test', 'purpose' => 'business-review']);
    $schema = (new Challenge)->getConnection()->getSchemaBuilder();
    $schema->table(Challenge::TABLE, function (Blueprint $table): void {
        $table->dropUnique('nvl_auth_challenges_secondary_secret_hash_unique');
        $table->dropColumn('secondary_secret_hash');
    });
    config(['nvl-auth.migrations.enabled' => false]);
    expect(fn () => app(AuthSchemaManager::class)->execute(true))->toThrow(RuntimeException::class, 'host-owned');
    expect($schema->hasColumn(Challenge::TABLE, 'secondary_secret_hash'))->toBeFalse();
    config(['nvl-auth.migrations.enabled' => true]);
    app(AuthSchemaManager::class)->execute(true);
    expect($schema->hasColumn(Challenge::TABLE, 'secondary_secret_hash'))->toBeTrue();
    expect(app(AuthChallenges::class)->consumeMagicLink(['recipient' => 'business@example.test', 'token' => $issued['secret']], 'business-review')->consumed_at)->not->toBeNull();
});

it('rejects substituted owner context and a resolver returning another proof subject', function (): void {
    $user = $this->user();
    $other = $this->user('other-proof@example.test');
    $context = $this->authenticationContext();
    $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    $forged = new AuthenticationRequestContext(guardName: 'web', sessionBinding: app('session.store')->getId(), requestedOwner: new OwnerReference('company', 'companies', 'int', '7'));
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $forged))->toThrow(AuthException::class);
    $this->app->instance(AuthSubjectResolver::class, new class($other) implements AuthSubjectResolver
    {
        public function __construct(private Authenticatable $subject) {}

        public function resolve(SubjectReference $reference): ?Authenticatable
        {
            return $this->subject;
        }
    });
    expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), auth()->guard('web'), app('session.store'), $context))->toThrow(AuthException::class);
    expect(auth()->guard('web')->check())->toBeFalse();
});

it('rejects a credential provider model outside the configured native principal contract', function (): void {
    $user = $this->user();
    config(['auth.providers.users.model' => ConfiguredOwnerUser::class]);
    $context = new AuthenticationRequestContext(tokenNamespace: 'native-contract', flowNonce: str_repeat('a', 64));
    expect(fn () => app(Authentication::class)->proveCredentialsForToken(['identifier' => $user->email, 'password' => 'correct-password'], $context))->toThrow(AuthException::class);
    expect(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(0);
});

it('redeems simultaneous native email challenges in their initiating browsers', function (string $method): void {
    config(['nvl-auth.features.magic_links.enabled' => true, 'nvl-auth.features.security_codes.enabled' => true]);
    $this->freezeSecond();
    $user = $this->user();
    $first = new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'first-browser');
    $second = new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'second-browser');
    $challenges = app(AuthChallenges::class);
    $request = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $one = $method === 'email_code' ? $challenges->requestSecurityCodeAuthentication($request, $first) : $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $first);
    $this->travel(1)->seconds();
    $two = $method === 'email_code' ? $challenges->requestSecurityCodeAuthentication($request, $second) : $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $second);
    foreach ([[$one, $first], [$two, $second]] as [$issued, $context]) {
        $proof = $method === 'email_code'
            ? $challenges->proveSecurityCodeAuthentication([...$request, 'code' => $issued['secret']], $context)
            : $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $method === 'fallback' ? $issued['fallbackCode'] : $issued['secret']], $context);
        expect($proof->reveal())->not->toBeEmpty();
    }
    expect(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(2);
})->with(['email_code', 'email_link', 'fallback']);

it('clears the previous factor continuation when a new password attempt fails', function (): void {
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $authentication = app(Authentication::class);
    $session = app('session.store');
    $this->authenticationContext();
    $guard = auth()->guard('web');
    expect(fn () => $authentication->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))->toThrow(AuthException::class, 'second factor');
    expect($authentication->hasPendingSecondFactor($session))->toBeTrue();
    expect(fn () => $authentication->login(['identifier' => $user->email, 'password' => 'incorrect'], [], $guard, $session))->toThrow(AuthException::class);
    expect($authentication->hasPendingSecondFactor($session))->toBeFalse();
});

it('records one attempt and terminal authentication fact for each complete password flow', function (string $destination, string $outcome): void {
    $user = $this->user();
    if ($outcome === 'missing_factor') {
        TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    }
    $events = [];
    foreach ([AuthenticationAttempted::class, AuthenticationRejected::class, UserAuthenticated::class] as $event) {
        Event::listen($event, function (object $fact) use (&$events): void {
            $events[] = $fact::class;
        });
    }
    if ($outcome === 'pipeline') {
        config(['nvl-auth.pipelines.login' => [RejectLoginStage::class]]);
    }
    $credentials = ['identifier' => $user->email, 'password' => $outcome === 'invalid' ? 'incorrect' : 'correct-password'];
    $this->authenticationContext();
    $complete = fn () => $destination === 'browser'
        ? app(Authentication::class)->login($credentials, [], auth()->guard('web'), app('session.store'))
        : app(Authentication::class)->loginWithToken($credentials, ['name' => 'Test', 'abilities' => ['profile:read']]);
    if ($outcome === 'success') {
        $complete();
    } else {
        expect($complete)->toThrow(AuthException::class);
    }
    expect(array_count_values($events))->toBe([
        AuthenticationAttempted::class => 1,
        ($outcome === 'success' ? UserAuthenticated::class : AuthenticationRejected::class) => 1,
    ]);
    expect(AuthAudit::query()->whereIn('action', ['authentication.failed', 'authentication.rejected'])->count())->toBe($outcome === 'success' ? 0 : 1)
        ->and(AuthAudit::query()->where('action', 'authentication.succeeded')->count())->toBe($outcome === 'success' ? 1 : 0);
})->with([['browser', 'success'], ['browser', 'invalid'], ['browser', 'pipeline'], ['token', 'success'], ['token', 'invalid'], ['token', 'pipeline'], ['token', 'missing_factor']]);

it('does not consume a pending recovery factor while session authentication is disabled', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = app(AuthSecondFactor::class)->regenerateRecoveryCodes($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::RecoveryRegeneration, 'correct-password')->reveal(), context: $this->authenticationContext());
    $this->authenticationContext();
    $authentication = app(Authentication::class);
    expect(fn () => $authentication->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store')))->toThrow(AuthException::class, 'second factor');
    config(['nvl-auth.features.sessions.enabled' => false]);
    expect(fn () => $authentication->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], auth()->guard('web'), app('session.store')))->toThrow(AuthException::class);
    expect(RecoveryCode::query()->whereNotNull('used_at')->count())->toBe(0);
    config(['nvl-auth.features.sessions.enabled' => true]);
    expect($authentication->completeSecondFactor(['recoveryCode' => $recovery->codes[0]], auth()->guard('web'), app('session.store'))->getAuthIdentifier())->toBe($user->id);
});

it('correlates concurrent social fixture intents with their own OAuth state', function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    $user = $this->user();
    $this->app->instance(SocialSubjectResolver::class, new TestSocialSubjectResolver($user));
    $provider = new class implements SocialIdentityProvider
    {
        public int $redirects = 0;

        public function redirectUrl(string $provider, ?string $callbackUrl, array $scopes, array $parameters): string
        {
            return 'https://provider.example/authorize?state=flow-'.++$this->redirects;
        }

        public function user(string $provider, ?string $callbackUrl): ExternalIdentity
        {
            return new ExternalIdentity($provider, 'state-user', email: 'claim@example.test', emailVerified: true, emailVerificationSource: 'fixture');
        }
    };
    $this->app->instance(SocialIdentityProviderFactory::class, new class($provider) implements SocialIdentityProviderFactory
    {
        public function __construct(private SocialIdentityProvider $provider) {}

        public function make(string $provider): SocialIdentityProvider
        {
            return $this->provider;
        }
    });
    $this->authenticationContext();
    $session = app('session.store');
    $controller = app(SocialIdentityController::class);
    $social = app(AuthSocialIdentities::class);
    $this->app->bind(OwnershipActorResolver::class, NativeOwnershipActorResolver::class);
    $this->app->bind(OwnerAvailability::class, ExistingOwnerAvailability::class);
    $intents = app(OwnerAuthenticationIntents::class);
    $request = Request::create('/social/github/redirect');
    $request->setLaravelSession($session);
    $controller->redirect('github', $request, $social, $intents, app(AuthenticationSessions::class));
    $first = Challenge::query()->where('type', 'social_authentication')->sole();
    $controller->redirect('github', $request, $social, $intents, app(AuthenticationSessions::class));
    $callback = Request::create('/social/github/callback?state=flow-1');
    $callback->setLaravelSession($session);
    $controller->callback('github', $callback, $social, app(AuthenticationSessions::class), app(AuthSubjectResolver::class));
    expect($first->refresh()->consumed_at)->not->toBeNull()
        ->and(Challenge::query()->where('type', 'social_authentication')->whereNull('consumed_at')->count())->toBe(1);
});

it('revokes an earlier native email challenge on same-browser reissue without erasing retained rows', function (string $method): void {
    config(['nvl-auth.features.magic_links.enabled' => true, 'nvl-auth.features.security_codes.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $request = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $first = $method === 'code' ? $challenges->requestSecurityCodeAuthentication($request, $context) : $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
    $second = $method === 'code' ? $challenges->requestSecurityCodeAuthentication($request, $context) : $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
    expect($first['challenge']->refresh()->revoked_at)->not->toBeNull()->and($first['challenge']->isUsable())->toBeFalse();
    if ($method !== 'code') {
        expect(fn () => $challenges->consumeMagicLinkAuthentication(['recipient' => null, 'challengeId' => $first['challenge']->identifier(), 'token' => $first['fallbackCode']], $context))->toThrow(AuthException::class);
        $proof = $challenges->consumeMagicLinkAuthentication(['recipient' => null, 'challengeId' => $second['challenge']->identifier(), 'token' => $second['fallbackCode']], $context);
    } else {
        $proof = $challenges->proveSecurityCodeAuthentication([...$request, 'code' => $second['secret']], $context);
    }
    expect($proof->reveal())->not->toBeEmpty()->and(Challenge::query()->where('type', $method === 'code' ? 'native_email_code' : 'native_email_link')->count())->toBe(2);
})->with(['code', 'fallback']);

it('preserves configured primary email settings and audit facts while final proofs keep native limits', function (string $method): void {
    $this->freezeSecond();
    $feature = $method === 'link' ? 'magic_links' : 'security_codes';
    $message = $method === 'link' ? 'magic_link' : 'security_code';
    config(["nvl-auth.features.{$feature}.enabled" => true, "nvl-auth.features.{$feature}.settings.ttl_minutes" => 9, "nvl-auth.features.{$feature}.settings.max_attempts" => 2, "nvl-auth.features.{$feature}.settings.digits" => 8, "nvl-auth.features.{$feature}.settings.fallback_code_digits" => 8]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $input = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $issued = $method === 'link' ? $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context) : $challenges->requestSecurityCodeAuthentication($input, $context);
    expect(strlen($method === 'link' ? $issued['fallbackCode'] : $issued['secret']))->toBe(8)
        ->and($issued['challenge']->max_attempts)->toBe(2)
        ->and($issued['challenge']->expires_at->equalTo(CarbonImmutable::now('UTC')->addMinutes(9)))->toBeTrue();
    if ($method === 'link') {
        expect($challenges->requestMagicLinkAuthentication(['recipient' => 'unknown@example.test'], $context))->toBeNull();
    }
    $redeem = fn (string $secret) => $method === 'link'
        ? $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $secret], $context)
        : $challenges->proveSecurityCodeAuthentication([...$input, 'code' => $secret], $context);
    expect(fn () => $redeem('incorrect'))->toThrow(AuthException::class);
    expect($issued['challenge']->refresh()->attempts)->toBe(1);
    $redeem($method === 'link' ? $issued['fallbackCode'] : $issued['secret']);
    $expected = $method === 'link' ? ['magic_links.issued', 'magic_links.requested', 'magic_links.requested', 'magic_link.failed', 'magic_link.consumed'] : ['security_codes.issued', 'security_code.failed', 'security_code.consumed'];
    expect(AuthAudit::query()->where('action', 'like', $method === 'link' ? 'magic%' : 'security_code%')->get()->pluck('action')->all())->toEqualCanonicalizing($expected);
    $proof = Challenge::query()->where('type', 'authentication_proof')->sole();
    expect($proof->max_attempts)->toBe(5)->and($proof->expires_at->equalTo(CarbonImmutable::now('UTC')->addSeconds(300)))->toBeTrue();
    foreach (AuthAudit::query()->get() as $audit) {
        expect(array_diff(array_keys($audit->metadata ?? []), ['challenge_id', 'purpose', 'matched']))->toBe([]);
    }
})->with(['link', 'code']);

it('keeps native email failed attempts and audits in the applicable outer transaction', function (bool $commit): void {
    config(['nvl-auth.features.security_codes.enabled' => true]);
    $user = $this->user();
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $input = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $issued = $challenges->requestSecurityCodeAuthentication($input, $context);
    $connection = $user->getConnection();
    $connection->beginTransaction();
    try {
        expect(fn () => $challenges->proveSecurityCodeAuthentication([...$input, 'code' => 'incorrect'], $context))->toThrow(AuthException::class);
        expect($issued['challenge']->refresh()->attempts)->toBe(1)
            ->and(AuthAudit::query()->where('action', 'security_code.failed')->count())->toBe(1);
        if ($commit) {
            $connection->commit();
        } else {
            $connection->rollBack();
        }
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }
    expect($issued['challenge']->refresh()->attempts)->toBe($commit ? 1 : 0)
        ->and(AuthAudit::query()->where('action', 'security_code.failed')->count())->toBe($commit ? 1 : 0);
})->with([true, false]);

it('defers native email host audits until commit and drops them on outer rollback', function (bool $commit): void {
    config(['nvl-auth.features.security_codes.enabled' => true]);
    $user = $this->user();
    $recorder = new HostAuditRecorder;
    app()->instance(AuthAuditRecorder::class, $recorder);
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $input = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $connection = $user->getConnection();
    $connection->beginTransaction();
    try {
        $issued = $challenges->requestSecurityCodeAuthentication($input, $context);
        expect(fn () => $challenges->proveSecurityCodeAuthentication([...$input, 'code' => 'incorrect'], $context))->toThrow(AuthException::class);
        $challenges->proveSecurityCodeAuthentication([...$input, 'code' => $issued['secret']], $context);
        expect($recorder->facts)->toBe([]);
        if ($commit) {
            $connection->commit();
        } else {
            $connection->rollBack();
        }
    } finally {
        if ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }
    }
    expect(array_column($recorder->facts, 'action'))->toBe($commit ? ['security_codes.issued', 'security_code.failed', 'security_code.consumed'] : []);
})->with([true, false]);

it('does not relabel committed native email consumption when its host audit observer fails', function (): void {
    config(['nvl-auth.features.security_codes.enabled' => true]);
    $user = $this->user();
    $recorder = new class implements AuthAuditRecorder
    {
        public array $actions = [];

        public function record(string $action, string $outcome = 'success', ?SubjectReference $subject = null, ?Authenticatable $actor = null, ?string $clientId = null, array $metadata = []): ?object
        {
            $this->actions[] = $action;
            if ($action === 'security_code.consumed') {
                throw new AuthException('observer_rejected', 'Observer failed after commit.', 422);
            }

            return null;
        }
    };
    app()->instance(AuthAuditRecorder::class, $recorder);
    $context = $this->authenticationContext();
    $challenges = app(AuthChallenges::class);
    $input = ['recipient' => $user->email, 'purpose' => 'passwordless_login'];
    $issued = $challenges->requestSecurityCodeAuthentication($input, $context);
    expect(fn () => $challenges->proveSecurityCodeAuthentication([...$input, 'code' => $issued['secret']], $context))->toThrow(AuthException::class, 'Observer failed');
    expect($issued['challenge']->refresh()->consumed_at)->not->toBeNull()
        ->and(Challenge::query()->where('type', 'authentication_proof')->count())->toBe(1)
        ->and($recorder->actions)->toBe(['security_codes.issued', 'security_code.consumed']);
});

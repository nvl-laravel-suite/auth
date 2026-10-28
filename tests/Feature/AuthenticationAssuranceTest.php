<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationProofs;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthenticationVerification;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use PragmaRX\Google2FA\Google2FA;

it('requires enrolled MFA even when the optional TOTP method is disabled', function (): void {
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    config(['nvl-auth.features.totp.enabled' => false]);
    $guard = auth()->guard('web');
    $session = app('session.store');
    $session->start();

    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], $guard, $session))
        ->toThrow(AuthException::class, 'second factor');
    expect($guard->check())->toBeFalse();
});

it('removes public raw principal session establishment', function (): void {
    expect(method_exists(AuthenticationSessions::class, 'establish'))->toBeFalse()
        ->and(method_exists(AuthenticationSessions::class, 'establishForPurpose'))->toBeFalse();
});

it('applies enrolled MFA to every native primary method and retains verified passkey UV', function (string $method): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.magic_links.enabled' => true, 'nvl-auth.features.security_codes.enabled' => true, 'nvl-auth.features.passkeys.enabled' => true, 'nvl-auth.features.passkeys.settings.require_user_verification' => false, 'nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    $user = $this->user();
    $session = app('session.store');
    $session->start();
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $session->getId());
    $guard = auth()->guard('web');
    $this->app->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
    if (str_contains($method, 'passkey')) {
        $passkeys = app(AuthPasskeys::class);
        $registration = $passkeys->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
        $passkeys->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    }
    $credential = TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    if ($method === 'password') {
        $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    } elseif (in_array($method, ['email_link', 'email_code'], true)) {
        $challenges = app(AuthChallenges::class);
        if ($method === 'email_link') {
            $issued = $challenges->requestMagicLinkAuthentication(['recipient' => $user->email], $context);
            $proof = $challenges->consumeMagicLinkAuthentication(['recipient' => $user->email, 'token' => $issued['secret']], $context);
        } else {
            $issued = $challenges->requestSecurityCodeAuthentication(['recipient' => $user->email, 'purpose' => 'passwordless_login'], $context);
            $proof = $challenges->proveSecurityCodeAuthentication(['recipient' => $user->email, 'purpose' => 'passwordless_login', 'code' => $issued['secret']], $context);
        }
    } elseif ($method === 'social') {
        $this->app->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
        $this->seedSocialIdentity($user, new ExternalIdentity('github', 'provider-user-123'));
        $social = app(AuthSocialAuthentication::class);
        $started = $social->beginLogin('github', $context);
        $proof = $social->completeLogin('github', $started['intent']->reveal(), $context)['proof'];
    } else {
        $options = $passkeys->beginAuthentication(context: $context);
        $completed = $passkeys->finishAuthentication(['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2, 'user_verified' => $method === 'uv_passkey']], sessionBinding: $session->getId());
        $proof = $completed['proof'];
    }
    if ($method === 'uv_passkey') {
        expect(app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), $guard, $session, $context)->getAuthIdentifier())->toBe($user->id);
    } else {
        expect(fn () => app(AuthenticationSessions::class)->establishFromProof($proof->reveal(), $guard, $session, $context))->toThrow(AuthException::class, 'second factor');
        expect($guard->check())->toBeFalse()->and(app(Authentication::class)->hasPendingSecondFactor($session))->toBeTrue();
        $code = (new Google2FA)->getCurrentOtp($credential->secret);
        expect(app(Authentication::class)->completeSecondFactor(['code' => $code], $guard, $session)->getAuthIdentifier())->toBe($user->id)
            ->and($guard->id())->toBe($user->id)
            ->and(app(Authentication::class)->hasPendingSecondFactor($session))->toBeFalse();
    }
})->with(['password', 'email_link', 'email_code', 'social', 'uv_passkey', 'non_uv_passkey']);

it('keeps credential fingerprints outside consumer assurance evidence representations', function (): void {
    $user = $this->user();
    $captured = [];
    $policy = Mockery::mock(AuthenticationAssurancePolicy::class);
    $policy->shouldReceive('assertSatisfied')->andReturnUsing(function ($subject, $evidence) use (&$captured): void {
        $captured[] = $evidence;
    });
    app()->instance(AuthenticationAssurancePolicy::class, $policy);
    app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store'));
    $fingerprint = app(SecretHasher::class)->hash('native-password-proof', $user->fresh()->getAuthPassword());
    $verification = AuthenticationVerification::fromChallenge(Challenge::query()->where('type', 'authentication_proof')->firstOrFail());
    ob_start();
    var_dump($verification);
    $debug = ob_get_clean();
    expect($debug)->not->toContain($fingerprint)
        ->and(get_object_vars($verification))->toHaveKeys(['evidence'])->not->toHaveKey('passwordBinding')
        ->and(fn () => json_encode($verification, JSON_THROW_ON_ERROR))->toThrow(LogicException::class)
        ->and(fn () => serialize($verification))->toThrow(LogicException::class)
        ->and($verification->matchesPasswordBinding($fingerprint))->toBeTrue()
        ->and($verification->matchesPasswordBinding('changed-credential'))->toBeFalse();
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: app('session.store')->getId());
    $proof = app(Authentication::class)->proveCredentials(['identifier' => $user->email, 'password' => 'correct-password'], $context);
    $consumed = app(AuthenticationProofs::class)->consume($proof->reveal(), AuthenticationDestination::Session, $context);
    expect(array_keys($consumed))->toBe(['subject', 'evidence']);
    expect($captured)->not->toBeEmpty();
    foreach ($captured as $evidence) {
        ob_start();
        var_dump($evidence);
        $debug = ob_get_clean();
        expect(get_object_vars($evidence))->not->toHaveKey('passwordBinding')
            ->and(json_encode($evidence, JSON_THROW_ON_ERROR))->not->toContain($fingerprint)
            ->and($debug)->not->toContain($fingerprint)
            ->and(serialize($evidence))->not->toContain($fingerprint);
    }
});

it('retains the credential snapshot across consumer assurance hooks', function (): void {
    $user = $this->user();
    $policy = Mockery::mock(AuthenticationAssurancePolicy::class);
    $policy->shouldReceive('assertSatisfied')->once()->andReturnUsing(function () use ($user): void {
        $user->newQuery()->whereKey($user->id)->update(['password' => password_hash('replacement-password', PASSWORD_BCRYPT, ['cost' => 4])]);
    });
    app()->instance(AuthenticationAssurancePolicy::class, $policy);
    expect(fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'correct-password'], [], auth()->guard('web'), app('session.store')))
        ->toThrow(AuthException::class, 'proof is invalid');
    expect(auth()->guard('web')->check())->toBeFalse();
});

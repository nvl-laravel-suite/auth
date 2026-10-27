<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\Tests\Fixtures\TestSocialSubjectResolver;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
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
        $registration = $passkeys->beginRegistration($user);
        $passkeys->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]]);
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
        $this->app->instance(SocialSubjectResolver::class, new TestSocialSubjectResolver($user));
        $social = app(AuthSocialIdentities::class);
        $started = $social->startAuthentication('github', $context);
        $proof = $social->finishAuthentication('github', $started['intent']->reveal(), $context);
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

<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Adapters\Passkeys\WebauthnPasskeyCeremony;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Providers\RouteServiceProvider;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\FeatureManifest;
use Nvl\Auth\Tests\Fixtures\TestWebauthnAuthenticator;

beforeEach(function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);
    config()->set('nvl-auth.features.passkeys.settings.relying_party_id', 'auth-package.test');
    config()->set('nvl-auth.features.passkeys.settings.relying_party_name', 'NVL Auth Test');
    config()->set('nvl-auth.features.passkeys.settings.origins', ['https://auth-package.test']);
    $this->app->forgetInstance(PasskeyCeremony::class);
});

it('provides complete browser registration options through the built-in adapter', function (): void {
    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    $adapter = app(PasskeyCeremony::class);

    expect($adapter)->toBeInstanceOf(WebauthnPasskeyCeremony::class)
        ->and($registration->options['rp'])->toMatchArray([
            'id' => 'auth-package.test',
            'name' => 'NVL Auth Test',
        ])
        ->and($registration->options['user'])->toMatchArray([
            'name' => 'user@example.test',
            'displayName' => 'Test User',
        ])
        ->and($registration->options['user']['id'])->toBeString()->not->toBe('1')
        ->and($registration->options['pubKeyCredParams'])->toBe([
            ['type' => 'public-key', 'alg' => -7],
            ['type' => 'public-key', 'alg' => -257],
        ])
        ->and($registration->options['authenticatorSelection'])->toMatchArray([
            'residentKey' => 'required',
            'userVerification' => 'required',
        ])
        ->and($registration->options['attestation'])->toBe('none')
        ->and($registration->options['timeout'])->toBe(60_000);
});

it('registers and authenticates a real ES256 WebAuthn credential end to end', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    $passkey = app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        $registration->ceremonyId,
        $authenticator->registrationResponse($registration->options),
        'Platform authenticator',
    );
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();
    $reference = app(FinishPasskeyAuthenticationAction::class)->execute(
        $authentication->ceremonyId,
        $authenticator->authenticationResponse(
            $authentication->options,
            $registration->options['user']['id'],
        ),
    );

    expect($passkey->credential_id)->toBe($authenticator->credentialId())
        ->and($passkey->transports)->toBe(['internal'])
        ->and($passkey->signature_counter)->toBe(0)
        ->and($reference->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(1)
        ->and($passkey->last_used_at)->not->toBeNull();
});

it('supports subject-scoped assertions without a returned user handle', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        $registration->ceremonyId,
        $authenticator->registrationResponse($registration->options),
    );
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute($user);
    $reference = app(FinishPasskeyAuthenticationAction::class)->execute(
        $authentication->ceremonyId,
        $authenticator->authenticationResponse($authentication->options, null),
    );

    expect($authentication->options['allowCredentials'])->toHaveCount(1)
        ->and($reference->identifier)->toBe((string) $user->getKey());
});

it('accepts authenticators that do not implement signature counters', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    $passkey = app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        $registration->ceremonyId,
        $authenticator->registrationResponse($registration->options),
    );
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();
    $reference = app(FinishPasskeyAuthenticationAction::class)->execute(
        $authentication->ceremonyId,
        $authenticator->authenticationResponse(
            $authentication->options,
            $registration->options['user']['id'],
            signatureCounter: 0,
        ),
    );

    expect($reference->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(0);
});

it('rejects wrong origins and invalid assertion signatures behind stable errors', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        $registration->ceremonyId,
        $authenticator->registrationResponse($registration->options),
    );
    $wrongOrigin = app(BeginPasskeyAuthenticationAction::class)->execute();

    try {
        app(FinishPasskeyAuthenticationAction::class)->execute(
            $wrongOrigin->ceremonyId,
            $authenticator->authenticationResponse(
                $wrongOrigin->options,
                $registration->options['user']['id'],
                origin: 'https://attacker.example',
            ),
        );

        throw new RuntimeException('The wrong WebAuthn origin was accepted.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_invalid')
            ->and($exception->getMessage())->not->toContain('origin');
    }

    $invalidSignature = app(BeginPasskeyAuthenticationAction::class)->execute();

    expect(fn () => app(FinishPasskeyAuthenticationAction::class)->execute(
        $invalidSignature->ceremonyId,
        $authenticator->authenticationResponse(
            $invalidSignature->options,
            $registration->options['user']['id'],
            validSignature: false,
        ),
    ))->toThrow(
        AuthException::class,
        'The passkey assertion was rejected.',
    );
});

it('rejects invalid challenges RP hashes and required user verification', function (): void {
    $authenticator = new TestWebauthnAuthenticator;
    $unverifiedUser = $this->user('unverified-passkey@example.test');
    $unverifiedRegistration = app(BeginPasskeyRegistrationAction::class)->execute($unverifiedUser);

    expect(fn () => app(FinishPasskeyRegistrationAction::class)->execute(
        $unverifiedUser,
        $unverifiedRegistration->ceremonyId,
        $authenticator->registrationResponse(
            $unverifiedRegistration->options,
            userVerified: false,
        ),
    ))->toThrow(AuthException::class, 'The passkey registration was rejected.');

    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        $registration->ceremonyId,
        $authenticator->registrationResponse($registration->options),
    );

    foreach ([
        ['challengeOverride' => 'aW52YWxpZC1jaGFsbGVuZ2U'],
        ['relyingPartyIdOverride' => 'attacker.example'],
        ['userVerified' => false],
    ] as $overrides) {
        $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();

        expect(fn () => app(FinishPasskeyAuthenticationAction::class)->execute(
            $authentication->ceremonyId,
            $authenticator->authenticationResponse(
                $authentication->options,
                $registration->options['user']['id'],
                ...$overrides,
            ),
        ))->toThrow(AuthException::class, 'The passkey assertion was rejected.');
    }
});

it('serves the complete built-in registration and authentication HTTP flow', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.routes.account.enabled', true);
    config()->set('nvl-auth.features.passkeys.routes.public.enabled', true);
    config()->set('nvl-auth.features.passkeys.routes.account.enabled', true);
    (new RouteServiceProvider(app()))->boot(
        app(Router::class),
        app(AuthConfiguration::class),
        app(FeatureManifest::class),
        app(FeatureGate::class),
    );
    Route::getRoutes()->refreshNameLookups();
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $this->actingAs($user, 'web');
    $registration = $this->postJson('/api/v1/auth/passkeys/registration/options')
        ->assertOk()
        ->assertJsonPath('code', 'passkey_registration_started');
    $registrationOptions = $registration->json('data.options');
    $registrationId = $registration->json('data.ceremony_id');

    expect($registrationOptions)->toBeArray()
        ->and($registrationId)->toBeString();

    $this->postJson('/api/v1/auth/passkeys/registration', [
        'ceremony_id' => $registrationId,
        'response' => $authenticator->registrationResponse($registrationOptions),
        'name' => 'HTTP passkey',
    ])->assertCreated()->assertJsonPath('code', 'passkey_registered');

    $authentication = $this->postJson('/api/v1/auth/passkeys/authentication/options')
        ->assertOk()
        ->assertJsonPath('code', 'passkey_authentication_started');
    $authenticationOptions = $authentication->json('data.options');
    $authenticationId = $authentication->json('data.ceremony_id');

    expect($authenticationOptions)->toBeArray()
        ->and($authenticationId)->toBeString();

    $this->postJson('/api/v1/auth/passkeys/authentication', [
        'ceremony_id' => $authenticationId,
        'response' => $authenticator->authenticationResponse(
            $authenticationOptions,
            $registrationOptions['user']['id'],
        ),
    ])->assertOk()
        ->assertJsonPath('code', 'passkey_authenticated')
        ->assertJsonPath('data.subject.id', (string) $user->getKey());
});

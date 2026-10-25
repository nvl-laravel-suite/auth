<?php

declare(strict_types=1);

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Nvl\Auth\Adapters\Passkeys\WebauthnPasskeyCeremony;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Tests\Fixtures\Consumer\FeatureManifest;
use Nvl\Auth\Tests\Fixtures\Consumer\RouteServiceProvider;
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
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
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
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    $passkey = app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => $authenticator->registrationResponse($registration->options), 'name' => 'Platform authenticator']
    );
    $authentication = app(AuthPasskeys::class)->beginAuthentication();
    $completed = app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => $authenticator->authenticationResponse(
            $authentication->options,
            $registration->options['user']['id']
        )]
    );

    expect($passkey->credential_id)->toBe($authenticator->credentialId())
        ->and($passkey->transports)->toBe(['internal'])
        ->and($passkey->signature_counter)->toBe(0)
        ->and($completed['subject']->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(1)
        ->and($passkey->last_used_at)->not->toBeNull();
});

it('supports subject-scoped assertions without a returned user handle', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => $authenticator->registrationResponse($registration->options)]
    );
    $authentication = app(AuthPasskeys::class)->beginAuthentication($user);
    $completed = app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => $authenticator->authenticationResponse($authentication->options, null)]
    );

    expect($authentication->options['allowCredentials'])->toHaveCount(1)
        ->and($completed['subject']->identifier)->toBe((string) $user->getKey());
});

it('accepts authenticators that do not implement signature counters', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    $passkey = app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => $authenticator->registrationResponse($registration->options)]
    );
    $authentication = app(AuthPasskeys::class)->beginAuthentication();
    $completed = app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => $authenticator->authenticationResponse(
            $authentication->options,
            $registration->options['user']['id'],
            signatureCounter: 0,
        )]
    );

    expect($completed['subject']->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(0);
});

it('rejects wrong origins and invalid assertion signatures behind stable errors', function (): void {
    $user = $this->user();
    $authenticator = new TestWebauthnAuthenticator;
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => $authenticator->registrationResponse($registration->options)]
    );
    $wrongOrigin = app(AuthPasskeys::class)->beginAuthentication();

    try {
        app(AuthPasskeys::class)->finishAuthentication(
            ['ceremonyId' => $wrongOrigin->ceremonyId, 'response' => $authenticator->authenticationResponse(
                $wrongOrigin->options,
                $registration->options['user']['id'],
                origin: 'https://attacker.example',
            )]
        );

        throw new RuntimeException('The wrong WebAuthn origin was accepted.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_invalid')
            ->and($exception->getMessage())->not->toContain('origin');
    }

    $invalidSignature = app(AuthPasskeys::class)->beginAuthentication();

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $invalidSignature->ceremonyId, 'response' => $authenticator->authenticationResponse(
            $invalidSignature->options,
            $registration->options['user']['id'],
            validSignature: false,
        )]
    ))->toThrow(
        AuthException::class,
        'The passkey assertion was rejected.',
    );
});

it('rejects invalid challenges RP hashes and required user verification', function (): void {
    $authenticator = new TestWebauthnAuthenticator;
    $unverifiedUser = $this->user('unverified-passkey@example.test');
    $unverifiedRegistration = app(AuthPasskeys::class)->beginRegistration($unverifiedUser);

    expect(fn () => app(AuthPasskeys::class)->finishRegistration(
        $unverifiedUser,
        ['ceremonyId' => $unverifiedRegistration->ceremonyId, 'response' => $authenticator->registrationResponse(
            $unverifiedRegistration->options,
            userVerified: false,
        )]
    ))->toThrow(AuthException::class, 'The passkey registration was rejected.');

    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => $authenticator->registrationResponse($registration->options)]
    );

    foreach ([
        ['challengeOverride' => 'aW52YWxpZC1jaGFsbGVuZ2U'],
        ['relyingPartyIdOverride' => 'attacker.example'],
        ['userVerified' => false],
    ] as $overrides) {
        $authentication = app(AuthPasskeys::class)->beginAuthentication();

        expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
            ['ceremonyId' => $authentication->ceremonyId, 'response' => $authenticator->authenticationResponse(
                $authentication->options,
                $registration->options['user']['id'],
                ...$overrides,
            )]
        ))->toThrow(AuthException::class, 'The passkey assertion was rejected.');
    }
});

it('serves the complete built-in registration and authentication HTTP flow', function (): void {
    app()->instance('routes.cached', false);
    config()->set('nvl-auth.routes.enabled', true);
    config()->set('nvl-auth.routes.public.enabled', true);
    config()->set('nvl-auth.routes.middleware', ['web']);
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
    $registration = $this->postJson('/nvl/api/v1/auth/passkeys/registration/options')
        ->assertOk()
        ->assertJsonPath('code', 'passkey_registration_started');
    $registrationOptions = $registration->json('data.options');
    $registrationId = $registration->json('data.ceremony_id');

    expect($registrationOptions)->toBeArray()
        ->and($registrationId)->toBeString();

    $this->postJson('/nvl/api/v1/auth/passkeys/registration', [
        'ceremonyId' => $registrationId,
        'response' => $authenticator->registrationResponse($registrationOptions),
        'name' => 'HTTP passkey',
    ])->assertCreated()->assertJsonPath('code', 'passkey_registered');

    $authentication = $this->postJson('/nvl/api/v1/auth/passkeys/authentication/options')
        ->assertOk()
        ->assertJsonPath('code', 'passkey_authentication_started');
    $authenticationOptions = $authentication->json('data.options');
    $authenticationId = $authentication->json('data.ceremony_id');

    expect($authenticationOptions)->toBeArray()
        ->and($authenticationId)->toBeString();

    $this->postJson('/nvl/api/v1/auth/passkeys/authentication', [
        'ceremonyId' => $authenticationId,
        'response' => $authenticator->authenticationResponse(
            $authenticationOptions,
            $registrationOptions['user']['id'],
        ),
    ])->assertOk()
        ->assertJsonPath('code', 'passkey_authenticated')
        ->assertJsonPath('data.subject.id', (string) $user->getKey());
});

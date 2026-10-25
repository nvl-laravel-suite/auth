<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;

beforeEach(function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);
    $this->app->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
});

it('persists verified passkeys and supplies stored material to the ceremony adapter', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    $passkey = app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true], 'name' => 'Laptop']
    );
    $authentication = app(AuthPasskeys::class)->beginAuthentication();
    $completed = app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]]
    );
    $adapter = app(PasskeyCeremony::class);

    expect($completed['subject']->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(2)
        ->and($passkey->getRawOriginal('credential_id'))->not->toBe('test-credential')
        ->and($passkey->getRawOriginal('public_key'))->not->toBe('test-public-key')
        ->and($adapter)->toBeInstanceOf(TestPasskeyCeremony::class)
        ->and($adapter->verifiedCredential?->publicKey)->toBe('test-public-key');
});

it('commits a failed passkey ceremony attempt before returning its neutral failure', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]]);
    $authentication = app(AuthPasskeys::class)->beginAuthentication();

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => false, 'credential_id' => 'test-credential', 'signature_counter' => 2]]
    ))->toThrow(AuthException::class);

    expect(Challenge::query()->where('type', 'passkey_authentication')->sole()->attempts)->toBe(1);
});

it('normalizes provider exceptions at the passkey boundary', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]]);
    $authentication = app(AuthPasskeys::class)->beginAuthentication();

    try {
        app(AuthPasskeys::class)->finishAuthentication(
            ['ceremonyId' => $authentication->ceremonyId, 'response' => [
                'valid' => true,
                'runtime_failure' => true,
                'credential_id' => 'test-credential',
                'signature_counter' => 2,
            ]]
        );

        throw new RuntimeException('The passkey provider failure was not normalized.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_invalid')
            ->and($exception->getMessage())->not->toContain('Provider details');
    }
});

it('enforces passkey uniqueness, credential limits, and user verification', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user);
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]]);

    $duplicate = app(AuthPasskeys::class)->beginRegistration($user);

    expect(fn () => app(AuthPasskeys::class)->finishRegistration(
        $user,
        ['ceremonyId' => $duplicate->ceremonyId, 'response' => ['valid' => true]]
    ))->toThrow(AuthException::class, 'already registered')
        ->and(Challenge::query()
            ->where('type', 'passkey_registration')
            ->where('secret_hash', app(SecretHasher::class)->hash('passkey-ceremony', $duplicate->ceremonyId))
            ->sole()
            ->attempts)->toBe(1);

    config()->set('nvl-auth.features.passkeys.settings.max_credentials_per_subject', 1);

    expect(fn () => app(AuthPasskeys::class)->beginRegistration($user))
        ->toThrow(AuthException::class, 'limit');

    $authentication = app(AuthPasskeys::class)->beginAuthentication();

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => [
            'valid' => true,
            'credential_id' => 'test-credential',
            'signature_counter' => 2,
            'user_verified' => false,
        ]]
    ))->toThrow(AuthException::class, 'rejected');
});

it('normalizes passkey start failures and rejects oversized browser input', function (): void {
    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony(failBegin: true));

    try {
        app(AuthPasskeys::class)->beginAuthentication();
        $this->fail('The passkey start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_provider_unavailable')
            ->and($exception->getMessage())->not->toContain('provider details');
    }

    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony);

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => 'ceremony', 'response' => ['payload' => str_repeat('x', 131_073)]]
    ))->toThrow(AuthException::class, 'input');
});

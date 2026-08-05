<?php

declare(strict_types=1);

use Nvl\Auth\Actions\Passkeys\BeginPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyRegistrationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passkeys\FinishPasskeyRegistrationAction;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Data\Mutations\FinishPasskeyAuthenticationData;
use Nvl\Auth\Data\Mutations\FinishPasskeyRegistrationData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;

beforeEach(function (): void {
    config()->set('nvl-auth.features.passkeys.enabled', true);
    $this->app->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
});

it('persists verified passkeys and supplies stored material to the ceremony adapter', function (): void {
    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    $passkey = app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        new FinishPasskeyRegistrationData($registration->ceremonyId, ['valid' => true], 'Laptop')
    );
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();
    $reference = app(FinishPasskeyAuthenticationAction::class)->execute(
        new FinishPasskeyAuthenticationData($authentication->ceremonyId, ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2])
    );
    $adapter = app(PasskeyCeremony::class);

    expect($reference->identifier)->toBe((string) $user->getKey())
        ->and($passkey->refresh()->signature_counter)->toBe(2)
        ->and($passkey->getRawOriginal('credential_id'))->not->toBe('test-credential')
        ->and($passkey->getRawOriginal('public_key'))->not->toBe('test-public-key')
        ->and($adapter)->toBeInstanceOf(TestPasskeyCeremony::class)
        ->and($adapter->verifiedCredential?->publicKey)->toBe('test-public-key');
});

it('commits a failed passkey ceremony attempt before returning its neutral failure', function (): void {
    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute($user, new FinishPasskeyRegistrationData($registration->ceremonyId, ['valid' => true]));
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();

    expect(fn () => app(FinishPasskeyAuthenticationAction::class)->execute(
        new FinishPasskeyAuthenticationData($authentication->ceremonyId, ['valid' => false, 'credential_id' => 'test-credential', 'signature_counter' => 2])
    ))->toThrow(AuthException::class);

    expect(Challenge::query()->where('type', 'passkey_authentication')->sole()->attempts)->toBe(1);
});

it('normalizes provider exceptions at the passkey boundary', function (): void {
    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute($user, new FinishPasskeyRegistrationData($registration->ceremonyId, ['valid' => true]));
    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();

    try {
        app(FinishPasskeyAuthenticationAction::class)->execute(
            new FinishPasskeyAuthenticationData($authentication->ceremonyId, [
                'valid' => true,
                'runtime_failure' => true,
                'credential_id' => 'test-credential',
                'signature_counter' => 2,
            ])
        );

        throw new RuntimeException('The passkey provider failure was not normalized.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_invalid')
            ->and($exception->getMessage())->not->toContain('Provider details');
    }
});

it('enforces passkey uniqueness, credential limits, and user verification', function (): void {
    $user = $this->user();
    $registration = app(BeginPasskeyRegistrationAction::class)->execute($user);
    app(FinishPasskeyRegistrationAction::class)->execute($user, new FinishPasskeyRegistrationData($registration->ceremonyId, ['valid' => true]));

    $duplicate = app(BeginPasskeyRegistrationAction::class)->execute($user);

    expect(fn () => app(FinishPasskeyRegistrationAction::class)->execute(
        $user,
        new FinishPasskeyRegistrationData($duplicate->ceremonyId, ['valid' => true])
    ))->toThrow(AuthException::class, 'already registered')
        ->and(Challenge::query()
            ->where('type', 'passkey_registration')
            ->where('secret_hash', app(SecretHasher::class)->hash('passkey-ceremony', $duplicate->ceremonyId))
            ->sole()
            ->attempts)->toBe(1);

    config()->set('nvl-auth.features.passkeys.settings.max_credentials_per_subject', 1);

    expect(fn () => app(BeginPasskeyRegistrationAction::class)->execute($user))
        ->toThrow(AuthException::class, 'limit');

    $authentication = app(BeginPasskeyAuthenticationAction::class)->execute();

    expect(fn () => app(FinishPasskeyAuthenticationAction::class)->execute(
        new FinishPasskeyAuthenticationData($authentication->ceremonyId, [
            'valid' => true,
            'credential_id' => 'test-credential',
            'signature_counter' => 2,
            'user_verified' => false,
        ])
    ))->toThrow(AuthException::class, 'rejected');
});

it('normalizes passkey start failures and rejects oversized browser input', function (): void {
    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony(failBegin: true));

    try {
        app(BeginPasskeyAuthenticationAction::class)->execute();
        $this->fail('The passkey start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_provider_unavailable')
            ->and($exception->getMessage())->not->toContain('provider details');
    }

    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony);

    expect(fn () => app(FinishPasskeyAuthenticationAction::class)->execute(
        new FinishPasskeyAuthenticationData('ceremony', ['payload' => str_repeat('x', 131_073)])
    ))->toThrow(AuthException::class, 'input');
});

<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
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
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $passkey = app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true], 'name' => 'Laptop'], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
    $completed = app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId());
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
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => false, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class);

    expect(Challenge::query()->where('type', 'passkey_authentication')->sole()->attempts)->toBe(1);
});

it('normalizes provider exceptions at the passkey boundary', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());

    try {
        app(AuthPasskeys::class)->finishAuthentication(
            ['ceremonyId' => $authentication->ceremonyId, 'response' => [
                'valid' => true,
                'runtime_failure' => true,
                'credential_id' => 'test-credential',
                'signature_counter' => 2,
            ]], sessionBinding: app('session.store')->getId());

        throw new RuntimeException('The passkey provider failure was not normalized.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_invalid')
            ->and($exception->getMessage())->not->toContain('Provider details');
    }
});

it('enforces passkey uniqueness, credential limits, and user verification', function (): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    $duplicate = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $duplicate->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'already registered')
        ->and(Challenge::query()
            ->where('type', 'passkey_registration')
            ->where('secret_hash', app(SecretHasher::class)->hash('passkey-ceremony', $duplicate->ceremonyId))
            ->sole()
            ->attempts)->toBe(1);

    config()->set('nvl-auth.features.passkeys.settings.max_credentials_per_subject', 1);

    expect(fn () => app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))
        ->toThrow(AuthException::class, 'limit');

    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => $authentication->ceremonyId, 'response' => [
            'valid' => true,
            'credential_id' => 'test-credential',
            'signature_counter' => 2,
            'user_verified' => false,
        ]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class, 'rejected');
});

it('normalizes passkey start failures and rejects oversized browser input', function (): void {
    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony(failBegin: true));

    try {
        app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
        $this->fail('The passkey start should fail.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_provider_unavailable')
            ->and($exception->getMessage())->not->toContain('provider details');
    }

    $this->app->instance(PasskeyCeremony::class, new TestPasskeyCeremony);

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(
        ['ceremonyId' => 'ceremony', 'response' => ['payload' => str_repeat('x', 131_073)]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class, 'input');
});

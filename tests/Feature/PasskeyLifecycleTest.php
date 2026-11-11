<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\Passkey;
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

it('rejects a signature counter that does not advance past a stored non-zero counter', function (int $replayedCounter): void {
    $user = $this->user();
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $passkey = app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $advance = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
    app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $advance->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 5]], sessionBinding: app('session.store')->getId());
    $cloned = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());

    try {
        app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $cloned->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => $replayedCounter]], sessionBinding: app('session.store')->getId());
        $this->fail('A non-advancing signature counter was accepted.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('passkey_counter_regression');
    }

    expect($passkey->refresh()->signature_counter)->toBe(5)
        ->and(Challenge::query()->where('type', 'passkey_authentication')->where('secret_hash', app(SecretHasher::class)->hash('passkey-ceremony', $cloned->ceremonyId))->sole()->attempts)->toBe(1);
})->with(['equal counter' => 5, 'lower counter' => 4, 'counter reset to zero' => 0]);

it('refuses a credential identifier that another principal already registered', function (): void {
    $owner = $this->user();
    $attacker = $this->user('passkey-attacker@example.test');
    $registration = app(AuthPasskeys::class)->beginRegistration($owner, grant: $this->recentGrant($owner, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $passkey = app(AuthPasskeys::class)->finishRegistration($owner, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'shared-credential']], grant: $this->recentGrant($owner, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());
    $duplicate = app(AuthPasskeys::class)->beginRegistration($attacker, grant: $this->recentGrant($attacker, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishRegistration($attacker, ['ceremonyId' => $duplicate->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'shared-credential']], grant: $this->recentGrant($attacker, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'already registered');

    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
    $completed = app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'shared-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId());

    expect(Passkey::query()->count())->toBe(1)
        ->and($passkey->refresh()->subject_id)->toBe((string) $owner->getKey())
        ->and($completed['subject']->identifier)->toBe((string) $owner->getKey());
});

it('binds a passkey ceremony to its subject, browser and ceremony type and consumes it once', function (): void {
    $user = $this->user();
    $other = $this->user('passkey-other@example.test');
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishRegistration($other, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($other, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'invalid or expired')
        ->and(fn () => app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class, 'invalid or expired');

    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'second-credential']], grant: $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), context: $this->authenticationContext()))->toThrow(AuthException::class, 'invalid or expired');

    $foreignBrowser = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $foreignBrowser->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: 'another-browser-session'))->toThrow(AuthException::class, 'browser binding');

    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
    $input = ['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]];
    app(AuthPasskeys::class)->finishAuthentication($input, sessionBinding: app('session.store')->getId());
    $input['response']['signature_counter'] = 3;

    expect(fn () => app(AuthPasskeys::class)->finishAuthentication($input, sessionBinding: app('session.store')->getId()))->toThrow(AuthException::class, 'invalid or expired')
        ->and(Passkey::query()->count())->toBe(1);
});

it('keeps ceremony identifiers, credential material, grants and proofs out of the audit trail', function (): void {
    $user = $this->user();
    $grants = [$this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal(), $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment, 'correct-password')->reveal()];
    $registration = app(AuthPasskeys::class)->beginRegistration($user, grant: $grants[0], context: $this->authenticationContext());
    app(AuthPasskeys::class)->finishRegistration($user, ['ceremonyId' => $registration->ceremonyId, 'response' => ['valid' => true]], grant: $grants[1], context: $this->authenticationContext());
    $authentication = app(AuthPasskeys::class)->beginAuthentication(context: $this->authenticationContext());
    $completed = app(AuthPasskeys::class)->finishAuthentication(['ceremonyId' => $authentication->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2]], sessionBinding: app('session.store')->getId());
    $audits = AuthAudit::query()->get();
    $trail = json_encode($audits->map(static fn (AuthAudit $audit): array => [$audit->action, $audit->outcome, $audit->metadata])->all(), JSON_THROW_ON_ERROR);

    expect($audits->pluck('action')->all())->toContain('passkey.registration_started', 'passkey.enrolled', 'passkey.authentication_started', 'passkey.authenticated');

    foreach ([$registration->ceremonyId, $authentication->ceremonyId, 'test-credential', 'test-public-key', 'test-user-handle', $completed['proof']->reveal(), 'correct-password', ...$grants] as $secret) {
        expect($trail)->not->toContain($secret);
    }
});

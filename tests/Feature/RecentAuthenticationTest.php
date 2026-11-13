<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Services\RecentAuthenticationProofs;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\TestPasskeyCeremony;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;

it('binds recent grants to one operation subject browser revision and exact expiry', function (string $change): void {
    $user = $this->user();
    $context = $this->authenticationContext();
    $purpose = RecentAuthenticationPurpose::PasswordChange;
    $grant = app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password'], $purpose, $context);
    if ($change === 'expiry') {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(300));
    } elseif ($change === 'revision') {
        $user->getConnection()->transaction(fn () => app(PrincipalSecurity::class)->advance($user, 'security_containment'));
    } elseif ($change === 'subject') {
        $user = $this->user('different@example.test');
    } elseif ($change === 'session') {
        $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: 'another-browser');
    } elseif ($change === 'guard') {
        $context = new AuthenticationRequestContext(guardName: 'other', sessionBinding: $context->sessionBinding);
    } elseif ($change === 'purpose') {
        $purpose = RecentAuthenticationPurpose::EmailChange;
    }
    $consume = fn () => $user->getConnection()->transaction(fn () => app(RecentAuthenticationProofs::class)->consume($user, $grant->reveal(), $purpose, $context));
    if ($change === 'replay') {
        $consume();
    }
    expect($consume)->toThrow(AuthException::class);
})->with(['expiry', 'revision', 'subject', 'session', 'guard', 'purpose', 'replay']);

it('rejects factor-only mixed primary and unavailable social confirmation', function (array $proof): void {
    expect(fn () => app(AuthReauthentication::class)->confirm($this->user(), $proof, RecentAuthenticationPurpose::PasswordChange, $this->authenticationContext()))->toThrow(isset($proof['socialProof']) ? AuthException::class : InvalidArgumentException::class);
})->with([[['code' => '123456']], [['recoveryCode' => 'recovery']], [['password' => 'correct-password', 'passkeyProof' => 'fake']], [['socialProof' => 'fake']]]);

it('keeps independently spent recovery proof spent when the sensitive mutation rolls back', function (): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true]);
    $user = $this->user();
    TotpCredential::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass()]);
    $recovery = RecoveryCode::factory()->forSubject($user)->create(['subject_type' => $user->getMorphClass(), 'code_hash' => app(SecretHasher::class)->hash('recovery-code', 'ONCE-ONLY')]);
    $context = $this->authenticationContext();
    $confirm = fn () => app(AuthReauthentication::class)->confirm($user, ['password' => 'correct-password', 'recoveryCode' => 'ONCE-ONLY'], RecentAuthenticationPurpose::PasswordChange, $context);
    expect(fn () => $user->getConnection()->transaction($confirm))
        ->toThrow(AuthException::class, 'enclosing source transaction');
    expect($recovery->refresh()->used_at)->toBeNull();

    $grant = $confirm();
    $data = ['password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password'];
    expect(fn () => $user->getConnection()->transaction(function () use ($user, $grant, $context, $data): void {
        app(AuthPasswords::class)->update($user, $data, $grant->reveal(), $context);
        throw new RuntimeException('rollback');
    }))->toThrow(RuntimeException::class, 'rollback');
    expect($recovery->refresh()->used_at)->not->toBeNull()
        ->and(password_verify('correct-password', $user->fresh()->getAuthPassword()))->toBeTrue();
    app(AuthPasswords::class)->update($user, $data, $grant->reveal(), $context);
    expect(password_verify('replacement-password', $user->fresh()->getAuthPassword()))->toBeTrue();
    expect(fn () => app(AuthPasswords::class)->update($user, $data, $grant->reveal(), $context))->toThrow(AuthException::class);
});

it('confirms a passwordless principal with a destination-bound verified UV passkey', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true]);
    app()->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
    $user = $this->user();
    $context = $this->authenticationContext();
    $service = app(AuthPasskeys::class);
    $options = $service->beginRegistration($user, $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment)->reveal(), $context);
    $service->finishRegistration($user, ['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true]], $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment)->reveal(), $context);
    $user->forceFill(['password' => null])->save();
    $ceremony = $service->beginReauthentication($user, $context);
    $verified = $service->finishAuthentication(['ceremonyId' => $ceremony->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2, 'user_verified' => true]], sessionBinding: $context->sessionBinding);
    $grant = app(AuthReauthentication::class)->confirm($user, ['passkeyProof' => $verified['proof']->reveal()], RecentAuthenticationPurpose::PasswordChange, $context);
    app(AuthPasswords::class)->update($user, ['password' => 'established-password', 'passwordConfirmation' => 'established-password'], $grant->reveal(), $context);
    expect(password_verify('established-password', $user->fresh()->getAuthPassword()))->toBeTrue();
    expect(fn () => app(AuthReauthentication::class)->confirm($user, ['passkeyProof' => $verified['proof']->reveal()], RecentAuthenticationPurpose::PasswordChange, $context))->toThrow(AuthException::class);
});

it('redacts recent grants and never accepts a browser password-confirmed timestamp as authority', function (): void {
    $user = $this->user();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange);
    ob_start();
    var_dump($grant);
    $debug = ob_get_clean();
    expect($debug)->not->toContain($grant->reveal())
        ->and(fn () => json_encode($grant, JSON_THROW_ON_ERROR))->toThrow(LogicException::class)
        ->and(fn () => serialize($grant))->toThrow(LogicException::class);
    app('session.store')->put('auth.password_confirmed_at', now()->timestamp);
    expect(fn () => app(AuthPasswords::class)->update($user, ['password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class);
});

it('rejects non UV passkey recent authentication even when ordinary passkey policy allows it', function (): void {
    config(['nvl-auth.features.passkeys.enabled' => true, 'nvl-auth.features.passkeys.settings.require_user_verification' => false]);
    app()->singleton(PasskeyCeremony::class, TestPasskeyCeremony::class);
    $user = $this->user();
    $context = $this->authenticationContext();
    $service = app(AuthPasskeys::class);
    $options = $service->beginRegistration($user, $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment)->reveal(), $context);
    $service->finishRegistration($user, ['ceremonyId' => $options->ceremonyId, 'response' => ['valid' => true]], $this->recentGrant($user, RecentAuthenticationPurpose::FactorEnrollment)->reveal(), $context);
    $user->forceFill(['password' => null])->save();
    $ceremony = $service->beginReauthentication($user, $context);
    $verified = $service->finishAuthentication(['ceremonyId' => $ceremony->ceremonyId, 'response' => ['valid' => true, 'credential_id' => 'test-credential', 'signature_counter' => 2, 'user_verified' => false]], sessionBinding: $context->sessionBinding);
    $count = Challenge::query()->where('type', 'recent_authentication')->count();
    expect(fn () => app(AuthReauthentication::class)->confirm($user, ['passkeyProof' => $verified['proof']->reveal()], RecentAuthenticationPurpose::PasswordChange, $context))->toThrow(AuthException::class);
    expect(Challenge::query()->where('type', 'recent_authentication')->count())->toBe($count);
});

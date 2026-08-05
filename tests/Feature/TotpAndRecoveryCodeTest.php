<?php

declare(strict_types=1);

use Nvl\Auth\Actions\RecoveryCodes\ConsumeRecoveryCodeAction;
use Nvl\Auth\Actions\RecoveryCodes\RegenerateRecoveryCodesAction;
use Nvl\Auth\Actions\Totp\ConfirmTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\StartTotpEnrollmentAction;
use Nvl\Auth\Actions\Totp\VerifyTotpAction;
use Nvl\Auth\Data\Mutations\ConfirmTotpEnrollmentData;
use Nvl\Auth\Data\Mutations\ConsumeRecoveryCodeData;
use Nvl\Auth\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Data\Mutations\VerifyTotpData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\RecoveryCode;
use PragmaRX\Google2FA\Google2FA;

it('enrolls verifies and replay-protects totp credentials', function (): void {
    config()->set('nvl-auth.features.totp.enabled', true);
    $user = $this->user();
    $enrollment = app(StartTotpEnrollmentAction::class)->execute($user, new StartTotpEnrollmentData($user->email));
    $code = app(Google2FA::class)->getCurrentOtp($enrollment->secret);
    $credential = app(ConfirmTotpEnrollmentAction::class)->execute(
        $user,
        $enrollment->credential,
        new ConfirmTotpEnrollmentData($code),
    );

    expect($credential->confirmed_at)->not->toBeNull()
        ->and(fn () => app(VerifyTotpAction::class)->execute($user, new VerifyTotpData($code)))
        ->toThrow(AuthException::class);

    expect(AuthAudit::query()->where('action', 'totp.failed')->where('outcome', 'failure')->exists())
        ->toBeTrue();
});

it('returns recovery codes once and consumes each hash once', function (): void {
    config()->set('nvl-auth.features.recovery_codes.enabled', true);
    $user = $this->user();
    $generated = app(RegenerateRecoveryCodesAction::class)->execute($user);

    expect($generated->codes)->toHaveCount(8)
        ->and(RecoveryCode::query()->count())->toBe(8);

    $record = app(ConsumeRecoveryCodeAction::class)->execute($user, new ConsumeRecoveryCodeData($generated->codes[0]));

    expect($record->used_at)->not->toBeNull()
        ->and(fn () => app(ConsumeRecoveryCodeAction::class)->execute($user, new ConsumeRecoveryCodeData($generated->codes[0])))
        ->toThrow(AuthException::class);
});

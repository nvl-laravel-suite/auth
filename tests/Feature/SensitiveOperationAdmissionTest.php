<?php

declare(strict_types=1);

use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthEmailChanges;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\AuthSocialLinks;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;

it('does not accept the old current password shortcut for a direct sensitive mutation', function (): void {
    $user = $this->user();
    expect(fn () => app(AuthPasswords::class)->update($user, ['currentPassword' => 'correct-password', 'password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password']))->toThrow(AuthException::class);
    expect(password_verify('correct-password', $user->fresh()->getAuthPassword()))->toBeTrue();
});

it('does not let a replacement account-confirmation policy bypass native grants', function (): void {
    $policy = Mockery::mock(AccountConfirmation::class);
    $policy->shouldReceive('assertConfirmed')->never();
    app()->instance(AccountConfirmation::class, $policy);
    $user = $this->user();
    expect(fn () => app(AuthPasswords::class)->update($user, ['password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password'], str_repeat('a', 64), $this->authenticationContext()))->toThrow(AuthException::class);
});

it('requires grants for direct sensitive self-service entrypoints', function (string $operation): void {
    config(['nvl-auth.features.totp.enabled' => true, 'nvl-auth.features.recovery_codes.enabled' => true, 'nvl-auth.features.passkeys.enabled' => true, 'nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.email_verification.enabled' => true]);
    $user = $this->user();
    config(['nvl-auth.features.social_identities.settings.providers.github' => ['scopes' => [], 'parameters' => []]]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory);
    $call = fn () => match ($operation) {
        'email' => app(AuthEmailChanges::class)->request($user, 'new@example.test', 'unproved', $this->authenticationContext()),
        'deletion' => app(AuthUsers::class)->deleteOwnAccount($user, [], auth()->guard('web'), app('session.store')),
        'enrollment' => app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email]),
        'recovery' => app(AuthSecondFactor::class)->regenerateRecoveryCodes($user),
        'passkey' => app(AuthPasskeys::class)->beginRegistration($user),
        'social' => app(AuthSocialLinks::class)->beginLink($user, 'github', 'unproved', $this->authenticationContext()),
    };
    expect($call)->toThrow(AuthException::class, 'operation-bound');
})->with(['email', 'deletion', 'enrollment', 'recovery', 'passkey', 'social']);

it('passes only safe verified evidence and purpose to host confirmation policy and rechecks its mutations', function (): void {
    $user = $this->user();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange);
    $policy = Mockery::mock(AccountConfirmation::class);
    $policy->shouldReceive('assertConfirmed')->once()->andReturnUsing(function ($subject, $evidence, $purpose) use ($user): void {
        expect($evidence)->toBeInstanceOf(AuthenticationEvidence::class)
            ->and(get_object_vars($evidence))->not->toHaveKey('passwordBinding')
            ->and($purpose)->toBe(RecentAuthenticationPurpose::PasswordChange);
        $user->newQuery()->whereKey($user->id)->update(['password' => password_hash('changed-by-hook', PASSWORD_BCRYPT, ['cost' => 4])]);
    });
    app()->instance(AccountConfirmation::class, $policy);
    expect(fn () => app(AuthPasswords::class)->update($user, ['password' => 'replacement-password', 'passwordConfirmation' => 'replacement-password'], $grant->reveal(), $this->authenticationContext()))->toThrow(AuthException::class);
});

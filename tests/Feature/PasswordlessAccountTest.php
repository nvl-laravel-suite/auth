<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthSocialAuthentication;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProvider;
use Nvl\Auth\Tests\Fixtures\TestSocialIdentityProviderFactory;
use Nvl\Auth\ValueObjects\ExternalIdentity;

it('sets an initial password using linked social step up and protects the last remaining primary', function (): void {
    config(['nvl-auth.features.social_identities.enabled' => true, 'nvl-auth.features.social_identities.settings.providers.google' => ['supports_reauthentication' => true]]);
    $user = $this->user();
    $user->update(['password' => null]);
    SocialIdentity::query()->create(['subject_type' => $user->getMorphClass(), 'subject_id' => $user->getKey(), 'provider' => 'google', 'provider_user_id' => 'social-only', 'provider_user_id_hash' => app(SecretHasher::class)->hash('social-identity-google', 'social-only'), 'profile' => []]);
    app()->instance(SocialIdentityProviderFactory::class, new TestSocialIdentityProviderFactory(new TestSocialIdentityProvider(identity: new ExternalIdentity('google', 'social-only'))));
    $context = $this->authenticationContext();
    $social = app(AuthSocialAuthentication::class);
    $start = $social->beginReauthentication($user, 'google', $context);
    $proof = $social->completeReauthentication($user, 'google', $start['intent']->reveal(), $context);
    $grant = app(AuthReauthentication::class)->confirm($user, ['socialProof' => $proof->reveal()], RecentAuthenticationPurpose::PasswordChange, $context);
    $passwords = app(AuthPasswords::class);
    $passwords->setInitial($user, ['password' => 'NewSecurePassword123', 'passwordConfirmation' => 'NewSecurePassword123'], $grant->reveal(), $context);
    expect(Hash::check('NewSecurePassword123', $user->refresh()->getAuthPassword()))->toBeTrue();
    $grant = $this->recentGrant($user, RecentAuthenticationPurpose::PasswordChange, 'NewSecurePassword123')->reveal();
    config(['nvl-auth.features.social_identities.settings.providers.google.enabled' => false]);
    expect(fn () => $passwords->remove($user, $grant, $context))->toThrow(AuthException::class);
    config(['nvl-auth.features.social_identities.settings.providers.google.enabled' => true]);
    $passwords->remove($user, $grant, $context);
    expect($user->refresh()->getAuthPassword())->toBeNull();
});

it('bounds self service profile and preference JSON just like management updates', function (): void {
    $user = $this->user();
    expect(fn () => app(AuthUsers::class)->updateProfile($user, ['profile' => ['oversized' => str_repeat('x', 70000)]]))->toThrow(InvalidArgumentException::class);
    expect($user->refresh()->profile)->toBeNull();
});

<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthAuditReader;
use Nvl\Auth\Services\AuthChallenges;
use Nvl\Auth\Services\AuthClients;
use Nvl\Auth\Services\AuthEmailVerification;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthInvitations;
use Nvl\Auth\Services\AuthPasskeys;
use Nvl\Auth\Services\AuthPasswords;
use Nvl\Auth\Services\AuthPermissions;
use Nvl\Auth\Services\AuthRegistration;
use Nvl\Auth\Services\AuthSecondFactor;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\ValueObjects\SubjectReference;

it('fails a representative Action for every disabled feature before database access', function (): void {
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $actions = [
        AuthFeature::Registration->value => fn () => app(AuthRegistration::class)->register([]),
        AuthFeature::Authentication->value => fn () => app(Authentication::class)->login(['identifier' => $user->email, 'password' => 'password'], [], auth()->guard('web'), app('session')->driver()),
        AuthFeature::Password->value => fn () => app(AuthPasswords::class)->requestReset(['identifier' => $user->email]),
        AuthFeature::EmailVerification->value => fn () => app(AuthEmailVerification::class)->request($user),
        AuthFeature::MagicLinks->value => fn () => app(AuthChallenges::class)->requestMagicLink(['recipient' => $user->email]),
        AuthFeature::SecurityCodes->value => fn () => app(AuthChallenges::class)->requestSecurityCode(['recipient' => $user->email, 'purpose' => 'login']),
        AuthFeature::Invitations->value => fn () => app(AuthInvitations::class)->preview('token'),
        AuthFeature::Totp->value => fn () => app(AuthSecondFactor::class)->startEnrollment($user, ['accountName' => $user->email]),
        AuthFeature::Passkeys->value => fn () => app(AuthPasskeys::class)->beginAuthentication(),
        AuthFeature::RecoveryCodes->value => fn () => app(AuthSecondFactor::class)->regenerateRecoveryCodes($user),
        AuthFeature::SocialIdentities->value => fn () => app(AuthSocialIdentities::class)->startAuthorization('github'),
        AuthFeature::Clients->value => fn () => app(AuthClients::class)->start(['clientId' => '00000000-0000-0000-0000-000000000000', 'flow' => 'login', 'returnPath' => '/']),
        AuthFeature::Sessions->value => fn () => app(AuthenticationSessions::class)->establishFromProof(str_repeat('a', 64), auth()->guard('web'), app('session')->driver(), $this->authenticationContext()),
        AuthFeature::ApiTokens->value => fn () => app(AuthTokens::class)->all($user),
        AuthFeature::Rbac->value => fn () => app(AuthPermissions::class)->synchronizeCatalog($user),
        AuthFeature::Audit->value => fn () => app(AuthAuditReader::class)->paginate($user),
    ];

    foreach ($actions as $feature => $action) {
        config()->set("nvl-auth.features.{$feature}.enabled", false);
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $action();
            throw new RuntimeException("Feature [{$feature}] did not fail closed.");
        } catch (AuthException) {
            expect(DB::getQueryLog())->toBe([], "Feature [{$feature}] queried before admission.");
        } finally {
            DB::disableQueryLog();
            config()->set("nvl-auth.features.{$feature}.enabled", true);
        }
    }
});

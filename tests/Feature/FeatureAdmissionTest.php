<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Actions\ApiTokens\ListApiTokensAction;
use Nvl\Auth\Actions\Audit\ListAuthAuditsAction;
use Nvl\Auth\Actions\Authentication\EstablishAuthenticatedSessionAction;
use Nvl\Auth\Actions\Authentication\LoginAction;
use Nvl\Auth\Actions\Authentication\RequestEmailVerificationAction;
use Nvl\Auth\Actions\Challenges\RequestMagicLinkAction;
use Nvl\Auth\Actions\Challenges\RequestSecurityCodeAction;
use Nvl\Auth\Actions\Clients\StartAuthClientAction;
use Nvl\Auth\Actions\Invitations\PreviewInvitationAction;
use Nvl\Auth\Actions\Passkeys\BeginPasskeyAuthenticationAction;
use Nvl\Auth\Actions\Passwords\RequestPasswordResetAction;
use Nvl\Auth\Actions\Rbac\SynchronizePermissionCatalogAction;
use Nvl\Auth\Actions\RecoveryCodes\RegenerateRecoveryCodesAction;
use Nvl\Auth\Actions\SocialIdentities\StartSocialAuthorizationAction;
use Nvl\Auth\Actions\Totp\StartTotpEnrollmentAction;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Data\Mutations\RequestMagicLinkData;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Data\Mutations\RequestSecurityCodeData;
use Nvl\Auth\Data\Mutations\StartClientAuthData;
use Nvl\Auth\Data\Mutations\StartTotpEnrollmentData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;

it('fails a representative Action for every disabled feature before database access', function (): void {
    $user = $this->user();
    $reference = SubjectReference::fromAuthenticatable($user);
    $actions = [
        AuthFeature::Authentication->value => fn () => app(LoginAction::class)->execute(new LoginData($user->email, 'password')),
        AuthFeature::Password->value => fn () => app(RequestPasswordResetAction::class)->execute(new RequestPasswordResetData($user->email)),
        AuthFeature::EmailVerification->value => fn () => app(RequestEmailVerificationAction::class)->execute($user),
        AuthFeature::MagicLinks->value => fn () => app(RequestMagicLinkAction::class)->execute(new RequestMagicLinkData($user->email)),
        AuthFeature::SecurityCodes->value => fn () => app(RequestSecurityCodeAction::class)->execute(new RequestSecurityCodeData($user->email, 'login')),
        AuthFeature::Invitations->value => fn () => app(PreviewInvitationAction::class)->execute('token'),
        AuthFeature::Totp->value => fn () => app(StartTotpEnrollmentAction::class)->execute($user, new StartTotpEnrollmentData($user->email)),
        AuthFeature::Passkeys->value => fn () => app(BeginPasskeyAuthenticationAction::class)->execute(),
        AuthFeature::RecoveryCodes->value => fn () => app(RegenerateRecoveryCodesAction::class)->execute($user),
        AuthFeature::SocialIdentities->value => fn () => app(StartSocialAuthorizationAction::class)->execute('github'),
        AuthFeature::Clients->value => fn () => app(StartAuthClientAction::class)->execute(new StartClientAuthData('00000000-0000-0000-0000-000000000000', 'login', '/')),
        AuthFeature::Sessions->value => fn () => app(EstablishAuthenticatedSessionAction::class)->execute($reference),
        AuthFeature::ApiTokens->value => fn () => app(ListApiTokensAction::class)->execute($user),
        AuthFeature::Rbac->value => fn () => app(SynchronizePermissionCatalogAction::class)->execute($user),
        AuthFeature::Audit->value => fn () => app(ListAuthAuditsAction::class)->execute($user),
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

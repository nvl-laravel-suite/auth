<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Users;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\UpdateProfileData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\PrincipalAttribute;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Events\PrincipalChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\User;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\UserLocator;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;
use Spatie\LaravelData\Optional;

/**
 * Updates the authenticated principal's self-service profile fields.
 */
final readonly class UpdateProfileAction
{
    /** Create the profile mutation use case. */
    public function __construct(
        private FeatureGate $features,
        private UserLocator $users,
        private AuthAuditRecorder $audits,
        private PrincipalAttributeMapper $attributes,
        private AccountConfirmation $confirmation,
        private AuthConfiguration $configuration,
    ) {}

    /** Persist self-service profile changes. */
    public function execute(Authenticatable $subject, UpdateProfileData $data): User
    {
        $this->features->assertAllowed(AuthFeature::PrincipalManagement, FeatureOperation::Update);
        $user = $this->users->authenticated($subject);

        return DB::connection($user->getConnectionName())->transaction(function () use ($data, $user): User {
            $attributes = $data->except('currentPassword')->toArray();
            $submittedEmail = $attributes['email'] ?? null;
            $currentEmail = $this->attributes->value($user, PrincipalAttribute::Email);
            $emailChanged = is_string($submittedEmail)
                && is_string($currentEmail)
                && mb_strtolower(trim($submittedEmail)) !== mb_strtolower(trim($currentEmail));

            if ($emailChanged) {
                if ($data->currentPassword instanceof Optional) {
                    throw new AuthException('account_confirmation_required', 'Email changes require account confirmation.', 422);
                }

                $this->confirmation->assertConfirmed($user, $data->currentPassword);
                $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);
                $normalizedEmail = mb_strtolower(trim($submittedEmail));

                if ($user::query()
                    ->where($this->attributes->column(PrincipalAttribute::Email), $normalizedEmail)
                    ->whereKeyNot($user->getKey())
                    ->exists()) {
                    throw new AuthException('email_unavailable', 'The email address is unavailable.', 422);
                }

                $attributes['emailVerified'] = false;
            }

            $user->update($this->attributes->map($attributes));
            $reference = SubjectReference::fromAuthenticatable($user);
            $this->audits->record('profile.updated', subject: $reference, actor: $user, metadata: [
                'attributes' => array_keys($attributes),
            ]);
            PrincipalChanged::dispatch($this->attributes->identifier($user), 'profile_updated', [
                'attributes' => array_keys($attributes),
            ]);

            if ($emailChanged) {
                $this->requestEmailVerification($user, $data);
            }

            return $user->refresh();
        }, 3);
    }

    /** Emit the post-commit verification delivery for one changed email address. */
    private function requestEmailVerification(User $user, UpdateProfileData $data): void
    {
        $expiresAt = CarbonImmutable::now()->addMinutes(
            $this->configuration->integerBetween('features.email_verification.settings.ttl_minutes', 60, 1, 10_080),
        );
        $reference = SubjectReference::fromAuthenticatable($user);
        AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
            messageId: (string) Str::uuid(),
            feature: AuthFeature::EmailVerification,
            type: AuthMessageType::EmailVerification,
            recipient: $user->getEmailForVerification(),
            payload: [
                'subject_type' => $reference->type,
                'subject_id' => $reference->identifier,
                'email_hash' => sha1($user->getEmailForVerification()),
            ],
            expiresAt: $expiresAt,
            locale: $data->locale instanceof Optional ? null : $data->locale,
        ));
        $this->audits->record('email_verification.requested', subject: $reference, actor: $user);
    }
}

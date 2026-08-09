<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passwords;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Hashing\Hasher;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Data\Mutations\ConfirmPasswordData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Confirms the current password in Laravel's browser session.
 */
final readonly class ConfirmPasswordAction
{
    /**
     * Create the password-confirmation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private Hasher $hasher,
        private BrowserSession $session,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Verify the current password and timestamp the active session.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] ConfirmPasswordData $data,
    ): void {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if (! $this->hasher->check($data->password, (string) $subject->getAuthPassword())) {
            $this->audits->record(
                'password.confirmation_failed',
                outcome: 'failure',
                subject: $reference,
                actor: $subject,
            );

            throw new AuthException('password_invalid', 'The current password is invalid.', 422);
        }

        if (! $this->session->confirmPassword()) {
            throw new AuthException(
                'session_unavailable',
                'Password confirmation requires an active browser session.',
                409,
            );
        }

        $this->audits->record('password.confirmed', subject: $reference, actor: $subject);
    }
}

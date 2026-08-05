<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passwords;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Hashing\Hasher;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Data\Mutations\UpdatePasswordData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthAuditRecorder;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Changes the current host subject's password after current-password proof.
 */
final readonly class UpdatePasswordAction
{
    /**
     * Create the password-update use case.
     */
    public function __construct(
        private FeatureGate $features,
        private Hasher $hasher,
        private PasswordUpdater $passwords,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Verify and replace the current password.
     */
    public function execute(
        Authenticatable&CanResetPassword $subject,
        #[SensitiveParameter] UpdatePasswordData $data,
    ): void {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Update);

        if (! $this->hasher->check($data->currentPassword, (string) $subject->getAuthPassword())) {
            throw new AuthException('password_invalid', 'The current password is invalid.', 422);
        }

        $this->passwords->update($subject, $data->password);
        $this->audits->record(
            'password.updated',
            subject: SubjectReference::fromAuthenticatable($subject),
            actor: $subject,
        );
    }
}

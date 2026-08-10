<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passwords;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;

/**
 * Consumes a Laravel password-broker token and updates the host credential.
 */
final readonly class ResetPasswordAction
{
    /**
     * Create the password reset use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $principalAttributes,
        private PasswordBrokerManager $brokers,
        private PasswordUpdater $passwords,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Reset a host-owned password through Laravel's broker.
     */
    public function execute(#[SensitiveParameter] ResetPasswordData $data): void
    {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $identifierName = $this->principalAttributes->identifierColumn(
            $this->configuration->string('identifier', 'email'),
        );
        $status = $this->pipeline->run(
            'password_reset',
            new AuthPipelineContext('password_reset', ['identifier_name' => $identifierName]),
            function () use ($data, $identifierName): string {
                $brokerName = $this->configuration->get('password_broker');
                $broker = $this->brokers->broker(is_string($brokerName) ? $brokerName : null);

                $status = $broker->reset(
                    [$identifierName => $data->identifier, 'token' => $data->token, 'password' => $data->password],
                    function (CanResetPassword $subject, string $newPassword): void {
                        $this->passwords->update($subject, $newPassword);

                        if ($subject instanceof Authenticatable) {
                            event(new PasswordReset($subject));
                            $this->audits->record(
                                'password.reset',
                                subject: SubjectReference::fromAuthenticatable($subject),
                            );
                        }
                    },
                );

                if (! is_string($status)) {
                    throw AuthException::invalidConfiguration('Laravel password broker returned an invalid status.');
                }

                return $status;
            },
        );

        if ($status !== PasswordBrokerContract::PASSWORD_RESET) {
            throw new AuthException('password_reset_invalid', 'The password reset token is invalid or expired.', 422);
        }
    }
}

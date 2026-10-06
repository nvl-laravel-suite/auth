<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passwords;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PasswordUpdater;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\ResetPasswordContract;
use Nvl\Auth\Data\Mutations\ResetPasswordData;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\EloquentPasswordUpdater;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use SensitiveParameter;

/**
 * Consumes a Laravel password-broker token and updates the host credential.
 *
 * @api
 */
final readonly class ResetPasswordAction implements ResetPasswordContract
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
        private AuthenticationEligibility $eligibility,
        private ConnectionCommitCallbacks $eventCommits,
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
                        if (! $subject instanceof Authenticatable) {
                            throw AuthException::invalidConfiguration(
                                'Password reset subjects must implement Laravel Authenticatable.',
                            );
                        }

                        try {
                            $this->eligibility->assertEligible($subject, AuthenticationPurpose::PasswordReset);
                        } catch (AuthException $exception) {
                            $this->audits->record(
                                'password.reset_rejected',
                                outcome: 'failure',
                                subject: SubjectReference::fromAuthenticatable($subject),
                                metadata: ['reason' => $exception->errorCode],
                            );

                            throw $exception;
                        }

                        $update = function () use ($subject, $newPassword): void {
                            $this->passwords->update($subject, $newPassword);

                            $event = new PasswordReset($subject);
                            if ($this->passwords instanceof EloquentPasswordUpdater && $subject instanceof Model) {
                                $this->eventCommits->afterCommit($subject->getConnection(), static function () use ($event): void {
                                    event($event);
                                });
                            } else {
                                event($event);
                            }
                            $this->audits->record(
                                'password.reset',
                                subject: SubjectReference::fromAuthenticatable($subject),
                            );
                        };
                        if ($this->passwords instanceof EloquentPasswordUpdater && $subject instanceof Model) {
                            $subject->getConnection()->transaction($update);
                        } else {
                            $update();
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

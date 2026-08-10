<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Auth\Passwords\PasswordBrokerManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Data\Mutations\RequestPasswordResetData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Creates a Laravel password-broker token and delegates its delivery by event.
 */
final readonly class RequestPasswordResetAction
{
    /**
     * Create the reset-request use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $principalAttributes,
        private PasswordBrokerManager $brokers,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Request a reset without revealing whether the identifier exists.
     */
    public function execute(RequestPasswordResetData $data, ?string $locale = null): void
    {
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Issue);
        $identifierName = $this->principalAttributes->identifierColumn(
            $this->configuration->string('identifier', 'email'),
        );
        $this->pipeline->run(
            'password_reset_requested',
            new AuthPipelineContext('password_reset_requested', ['identifier_name' => $identifierName]),
            function () use ($data, $identifierName, $locale): void {
                $brokerName = $this->configuration->get('password_broker');
                $broker = $this->brokers->broker(is_string($brokerName) ? $brokerName : null);

                if (! $broker instanceof PasswordBroker) {
                    throw new \LogicException('The configured password broker must use Laravel\'s password broker implementation.');
                }

                $subject = $broker->getUser([$identifierName => $data->identifier]);

                if (! $subject instanceof CanResetPassword) {
                    $this->audits->record('password.reset_requested', metadata: ['matched' => false]);

                    return;
                }

                $token = $broker->createToken($subject);
                $expiresAt = CarbonImmutable::now()->addMinutes(
                    $this->configuration->integerBetween(
                        'features.password.settings.reset_ttl_minutes',
                        60,
                        1,
                        10_080,
                    ),
                );
                AuthDeliveryRequested::dispatch(new AuthDeliveryRequest(
                    messageId: (string) Str::uuid(),
                    feature: AuthFeature::Password,
                    type: AuthMessageType::PasswordReset,
                    recipient: $subject->getEmailForPasswordReset(),
                    payload: ['token' => $token, 'identifier' => $data->identifier],
                    expiresAt: $expiresAt,
                    locale: $locale,
                ));
                $reference = $subject instanceof Authenticatable
                    ? SubjectReference::fromAuthenticatable($subject)
                    : null;
                $this->audits->record(
                    'password.reset_requested',
                    subject: $reference,
                    metadata: ['matched' => true],
                );
            },
        );
    }
}

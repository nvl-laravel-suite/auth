<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\PrincipalEligibility;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use SensitiveParameter;
use Throwable;

/**
 * Authenticates a browser user through the configured Laravel guard.
 */
final readonly class LoginAction
{
    /**
     * Create the stateful login use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private PrincipalAttributeMapper $principalAttributes,
        private AuthManager $auth,
        private BrowserSession $session,
        private AuthPipeline $pipeline,
        private AuthAuditRecorder $audits,
        private PrincipalEligibility $eligibility,
        private SuccessfulLoginMetadataRecorder $loginMetadata,
    ) {}

    /**
     * Authenticate one identifier and regenerate the Laravel session identifier.
     */
    public function execute(
        #[SensitiveParameter] LoginData $data,
        ?AuthenticationRequestContext $requestContext = null,
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $identifierName = $this->principalAttributes->identifierColumn(
            $this->configuration->string('identifier', 'email'),
        );
        $guard = $this->auth->guard($this->configuration->string('guard', 'web'));

        if (! $guard instanceof StatefulGuard) {
            throw AuthException::invalidConfiguration(
                'The configured Auth login guard must be stateful.',
            );
        }

        AuthenticationAttempted::dispatch($identifierName, $data->identifier);

        if (! $guard->attempt([$identifierName => $data->identifier, 'password' => $data->password], $data->remember)) {
            $this->audits->record('authentication.failed', outcome: 'failure');
            AuthenticationRejected::dispatch($identifierName, $data->identifier, 'credentials_invalid');
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }

        $subject = $guard->user();

        if (! $subject instanceof Authenticatable) {
            $guard->logout();
            throw AuthException::invalidConfiguration('The configured guard returned no authenticated subject.');
        }

        try {
            $this->eligibility->assertAuthenticationAllowed($subject);
        } catch (AuthException $exception) {
            $guard->logout();
            $this->audits->record('authentication.failed', outcome: 'failure');
            AuthenticationRejected::dispatch(
                $identifierName,
                $data->identifier,
                $exception->errorCode,
                SubjectReference::fromAuthenticatable($subject),
            );

            throw $exception;
        }

        $this->loginMetadata->record($subject, $requestContext ?? new AuthenticationRequestContext);

        $reference = SubjectReference::fromAuthenticatable($subject);

        try {
            return $this->pipeline->run(
                'login',
                new AuthPipelineContext(
                    'login',
                    ['identifier_name' => $identifierName, 'remember' => $data->remember],
                    $reference,
                ),
                function () use ($reference, $subject): Authenticatable {
                    $this->session->regenerateIdentifier();
                    $this->audits->record('authentication.succeeded', subject: $reference, actor: $subject);
                    UserAuthenticated::dispatch($reference);

                    return $subject;
                },
            );
        } catch (Throwable $exception) {
            $guard->logout();
            $this->audits->record(
                'authentication.rejected',
                outcome: 'failure',
                subject: $reference,
                actor: $subject,
            );
            AuthenticationRejected::dispatch(
                $identifierName,
                $data->identifier,
                'pipeline_rejected',
                $reference,
            );

            throw $exception;
        }
    }
}

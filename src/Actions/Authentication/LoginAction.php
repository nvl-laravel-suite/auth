<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\BrowserSession;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Data\Mutations\LoginData;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
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
        private AuthenticationEligibility $eligibility,
        private SuccessfulLoginMetadataRecorder $loginMetadata,
        private AuthOperationBoundary $operations,
        private TenantAuthenticationIntents $tenantIntents,
        private TenantMembershipAccess $tenantMemberships,
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
        $this->operations->central(AuthIdentityOperation::Login);
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
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
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

        $reference = SubjectReference::fromAuthenticatable($subject);
        $this->operations->central(AuthIdentityOperation::Login, $subject);

        try {
            $authenticated = $this->pipeline->run(
                'login',
                new AuthPipelineContext(
                    'login',
                    ['identifier_name' => $identifierName, 'remember' => $data->remember],
                    $reference,
                ),
                fn (): Authenticatable => $subject,
            );
            $this->session->regenerateIdentifier();
            $this->loginMetadata->record($authenticated, $requestContext ?? new AuthenticationRequestContext);
            $this->audits->record('authentication.succeeded', subject: $reference, actor: $authenticated);
            $this->selectTenant($authenticated, $reference, $requestContext);
            UserAuthenticated::dispatch($reference);

            return $authenticated;
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

    /** Treat tenant selection as a separate, non-escalating result of global login. */
    private function selectTenant(
        Authenticatable $subject,
        SubjectReference $reference,
        ?AuthenticationRequestContext $context,
    ): void {
        if (config('tenancy.enabled') !== true
            || ! is_string($context?->tenantIntentNonce)
            || ! is_string($context->tenantSessionBinding)
            || $context->tenantPurpose === null) {
            return;
        }
        try {
            $tenant = $this->tenantIntents->consume(
                $context->tenantIntentNonce,
                $context->tenantPurpose,
                $context->tenantSessionBinding,
                $context->tenantIntentSubjectBound ? $reference : null,
                $context->tenantProvider,
            );
            if ($context->requestedTenant !== null && $context->requestedTenant->value !== $tenant->value) {
                throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
            }
            $this->tenantMemberships->assertMember($subject, $tenant);
            $this->audits->record(
                'authentication.tenant_selected',
                subject: $reference,
                actor: $subject,
                metadata: ['tenant_id' => $tenant->value],
            );
        } catch (Throwable) {
            $this->audits->record(
                'authentication.tenant_selection_denied',
                outcome: 'denied',
                subject: $reference,
                actor: $subject,
            );
        }
    }
}

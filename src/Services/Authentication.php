<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Contracts\SuccessfulLoginMetadataRecorder;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Events\AuthenticationAttempted;
use Nvl\Auth\Events\AuthenticationRejected;
use Nvl\Auth\Events\UserAuthenticated;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;
use SensitiveParameter;
use Throwable;

/**
 * Authenticates a browser user through the configured Laravel guard.
 *
 * @api
 */
final readonly class Authentication
{
    /**
     * Create the stateful login use case.
     */
    public function __construct(private FeatureGate $features, private OwnerAuthenticationSelection $ownerSelection, private AuthConfiguration $configuration, private PrincipalAttributeMapper $principalAttributes, private AuthManager $auth, private AuthPipeline $pipeline, private AuthAuditRecorder $audits, private AuthenticationEligibility $eligibility, private SuccessfulLoginMetadataRecorder $loginMetadata, private AuthOperationBoundary $operations, private DomainEventDispatcher $domainEvents) {}

    /**
     * Authenticate one identifier and regenerate the Laravel session identifier.
     *
     * @param  array<string, mixed>  $credentials
     * @param  array{remember?: mixed, ipAddress?: string|null, userAgent?: string|null, requestId?: string|null, ownerIntentNonce?: string|null, ownerSessionBinding?: string|null, requestedOwner?: OwnerReference|null, ownerPurpose?: OwnerAuthenticationPurpose|null, ownerIntentSubjectBound?: bool, ownerProvider?: string|null}  $context
     */
    public function login(
        #[SensitiveParameter]
        array $credentials,
        array $context,
        StatefulGuard $guard,
        Session $session
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::Login);
        $identifierName = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $remember = $context['remember'] ?? false;
        if (! is_bool($remember)) {
            throw new \InvalidArgumentException('Remember must be boolean.');
        }
        unset($context['remember']);
        $requestContext = new AuthenticationRequestContext(...$context);
        $identifier = is_string($credentials['identifier'] ?? null) ? $credentials['identifier'] : '';
        $this->domainEvents->dispatch(new AuthenticationAttempted($identifierName, $identifier), (new AuthAudit)->getConnection());
        try {
            $subject = $this->verifyCredentials($credentials);
        } catch (AuthException $exception) {
            $this->audits->record('authentication.failed', outcome: 'failure');
            $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, 'credentials_invalid'), (new AuthAudit)->getConnection());
            throw $exception;
        }
        try {
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
        } catch (AuthException $exception) {
            $guard->logout();
            $this->audits->record('authentication.failed', outcome: 'failure');
            $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, $exception->errorCode, SubjectReference::fromAuthenticatable($subject)), (new AuthAudit)->getConnection());
            throw $exception;
        }
        $reference = SubjectReference::fromAuthenticatable($subject);
        $this->operations->central(AuthIdentityOperation::Login, $subject);
        try {
            $authenticated = $this->pipeline->run('login', new AuthPipelineContext('login', ['identifier_name' => $identifierName, 'remember' => $remember], $reference), fn (): Authenticatable => $subject);
            $guard->login($authenticated, $remember);
            $session->regenerate(true);
            $this->loginMetadata->record($authenticated, $requestContext);
            $this->audits->record('authentication.succeeded', subject: $reference, actor: $authenticated);
            $this->ownerSelection->select($authenticated, $requestContext, OwnerAuthenticationPurpose::Login);
            $this->domainEvents->dispatch(new UserAuthenticated($reference), (new AuthAudit)->getConnection());

            return $authenticated;
        } catch (Throwable $exception) {
            $guard->logout();
            $this->audits->record('authentication.rejected', outcome: 'failure', subject: $reference, actor: $subject);
            $this->domainEvents->dispatch(new AuthenticationRejected($identifierName, $identifier, 'pipeline_rejected', $reference), (new AuthAudit)->getConnection());
            throw $exception;
        }
    }

    /** Verify credentials without creating a session.
     * @param  array<string, mixed>  $credentials
     */
    public function verifyCredentials(
        #[SensitiveParameter]
        array $credentials
    ): Authenticatable {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Password, FeatureOperation::Use);
        if (array_diff(array_keys($credentials), ['identifier', 'password']) !== [] || ! is_string($credentials['identifier'] ?? null) || trim($credentials['identifier']) === '' || strlen($credentials['identifier']) > 255 || ! is_string($credentials['password'] ?? null) || $credentials['password'] === '' || strlen($credentials['password']) > 4096) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $identifier = $this->principalAttributes->identifierColumn($this->configuration->string('identifier', 'email'));
        $provider = $this->auth->createUserProvider($this->configuration->string('provider', 'users'));
        if ($provider === null) {
            throw AuthException::invalidConfiguration('A credential provider is required.');
        }
        $native = [$identifier => $credentials['identifier'], 'password' => $credentials['password']];
        $subject = $provider->retrieveByCredentials($native);
        if ($subject === null || ! $provider->validateCredentials($subject, $native)) {
            throw new AuthException('credentials_invalid', 'The supplied credentials are invalid.', 422);
        }
        $provider->rehashPasswordIfRequired($subject, $native);

        return $subject;
    }
}

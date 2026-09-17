<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\SocialIdentityProvider;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthOperationBoundary;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SocialProviderConfiguration;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Exceptions\TenantInactive;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantId;
use Throwable;

/**
 * Orchestrates provider acquisition, subject resolution, and canonical identity linking.
 */
final readonly class CompleteSocialAuthorizationAction
{
    /**
     * Create the social callback use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SocialProviderConfiguration $configuration,
        private SocialIdentityProvider $provider,
        private SocialSubjectResolver $subjects,
        private LinkSocialIdentityAction $links,
        private AuthOperationBoundary $operations,
        private TenantAuthenticationIntents $intents,
        private TenantAuthenticationSession $session,
        private TenantMembershipAccess $memberships,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Acquire provider claims and link them to a supplied or resolved host subject.
     */
    public function execute(
        string $provider,
        ?Authenticatable $subject = null,
        ?string $flowReference = null,
        ?TenantId $requestedTenant = null,
    ): SocialIdentity {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::SocialIdentity, $subject);
        $configuration = $this->configuration->provider($provider);

        try {
            $identity = $this->provider->user($provider, $configuration['callback_url']);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException(
                'social_authorization_failed',
                'The social authorization could not be completed.',
                422,
                previous: $exception,
            );
        }

        if ($subject === null && $identity->email !== null && ! $identity->emailVerified) {
            throw new AuthException(
                'social_email_unverified',
                'The social provider did not prove the returned email address.',
                422,
            );
        }

        $resolvedSubject = $subject ?? $this->subjects->resolve($identity);
        $record = $this->links->execute($resolvedSubject, $identity);
        if (config('tenancy.enabled') === true && is_string($flowReference) && trim($flowReference) !== '') {
            $flow = "social:{$provider}:{$flowReference}";
            $nonce = $this->session->pullAuthenticationIntent($flow);
            if (is_string($nonce)) {
                try {
                    $tenant = $this->intents->consume(
                        $nonce,
                        TenantAuthenticationPurpose::SocialLogin,
                        $this->session->authenticationFlowBinding($flow),
                        provider: $provider,
                    );
                    if ($requestedTenant instanceof TenantId && $requestedTenant->value !== $tenant->value) {
                        throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
                    }
                    $this->memberships->assertMember($resolvedSubject, $tenant);
                    $this->audits->record(
                        'authentication.tenant_selected',
                        subject: SubjectReference::fromAuthenticatable($resolvedSubject),
                        actor: $resolvedSubject,
                        metadata: ['tenant_id' => $tenant->value, 'provider' => $provider],
                    );
                } catch (AuthException|TenantInactive|TenantNotFound) {
                    $this->audits->record(
                        'authentication.tenant_selection_denied',
                        outcome: 'denied',
                        subject: SubjectReference::fromAuthenticatable($resolvedSubject),
                        actor: $resolvedSubject,
                        metadata: ['provider' => $provider],
                    );
                } finally {
                    $this->session->forgetAuthenticationFlowBinding($flow);
                }
            }
        }

        return $record;
    }
}

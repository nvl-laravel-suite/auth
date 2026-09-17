<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Authentication;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthConfiguration;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\TenantAuthenticationIntents;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\ValueObjects\TenantId;
use Throwable;

/**
 * Completes one server-owned pending tenant selection after global authentication.
 */
final readonly class CompletePendingTenantAuthenticationIntentAction
{
    /** Create the pending tenant-selection use case. */
    public function __construct(
        private FeatureGate $features,
        private AuthConfiguration $configuration,
        private AuthManager $auth,
        private TenantAuthenticationSession $session,
        private TenantAuthenticationIntents $intents,
        private TenantMembershipAccess $memberships,
        private AuthAuditRecorder $audits,
    ) {}

    /** Consume the authenticated session's pending intent for the expected tenant. */
    public function execute(?TenantId $expectedTenant): TenantId
    {
        $this->features->assertAllowed(AuthFeature::Authentication, FeatureOperation::Use);
        $this->features->assertAllowed(AuthFeature::Sessions, FeatureOperation::Use);
        if (config('tenancy.enabled') !== true) {
            throw new AuthException('tenant_authentication_intent_unavailable', 'No tenant authentication intent is pending.', 410);
        }

        $subject = $this->auth->guard($this->configuration->string('guard', 'web'))->user();
        if (! $subject instanceof Authenticatable) {
            throw new AuthException('authentication_required', 'Authentication is required.', 401);
        }
        $reference = SubjectReference::fromAuthenticatable($subject);
        if (! $expectedTenant instanceof TenantId) {
            $this->deny($subject, $reference);
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }
        $pending = $this->session->pendingTenantAuthenticationIntent($expectedTenant, $reference);
        if ($pending === null) {
            throw new AuthException('tenant_authentication_intent_unavailable', 'No tenant authentication intent is pending.', 410);
        }

        $consumed = false;
        try {
            $tenant = $this->intents->consume(
                $pending->nonce,
                $pending->purpose,
                $pending->sessionBinding,
                $expectedTenant,
                $pending->subjectBound ? $reference : null,
                $pending->provider,
            );
            $consumed = true;
            $this->memberships->assertMember($subject, $tenant);
        } catch (Throwable $exception) {
            if ($consumed) {
                $this->session->forgetPendingTenantAuthenticationIntent($pending);
            }
            $this->deny($subject, $reference);

            throw $exception instanceof AuthException
                ? $exception
                : new AuthException(
                    'tenant_authentication_intent_invalid',
                    'The tenant authentication intent is invalid.',
                    410,
                    previous: $exception,
                );
        }

        $this->session->forgetPendingTenantAuthenticationIntent($pending);
        $this->audits->record(
            'authentication.tenant_selected',
            subject: $reference,
            actor: $subject,
            metadata: ['tenant_id' => $tenant->value],
        );

        return $tenant;
    }

    /** Record a non-escalating tenant selection denial. */
    private function deny(Authenticatable $subject, SubjectReference $reference): void
    {
        $this->audits->record(
            'authentication.tenant_selection_denied',
            outcome: 'denied',
            subject: $reference,
            actor: $subject,
        );
    }
}

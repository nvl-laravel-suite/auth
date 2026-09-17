<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Nvl\Auth\Contracts\TenantAuthenticationSession;
use Nvl\Auth\Enums\TenantAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Stores tenant intent references only in encrypted, server-owned challenge state. */
final readonly class TenantAuthenticationChallengeIntents
{
    private const string PAYLOAD_KEY = '_tenant_authentication_intent';

    public function __construct(
        private TenantAuthenticationIntents $intents,
        private TenantAuthenticationSession $session,
    ) {}

    public function attach(
        Challenge $challenge,
        ?TenantId $tenant,
        TenantAuthenticationPurpose $purpose,
        string $provider,
        ?SubjectReference $subject = null,
    ): void {
        if (config('tenancy.enabled') !== true || ! $tenant instanceof TenantId) {
            return;
        }

        $flow = $this->flow($provider, $challenge->identifier());
        $issued = $this->intents->issue(
            $tenant,
            $purpose,
            $this->session->authenticationFlowBinding($flow),
            $subject,
            $provider,
        );
        $payload = is_array($challenge->payload) ? $challenge->payload : [];
        $payload[self::PAYLOAD_KEY] = [
            'nonce' => $issued->nonce,
            'purpose' => $purpose->value,
            'provider' => $provider,
            'subject_bound' => $subject instanceof SubjectReference,
            'tenant_id' => $tenant->value,
            'expires_at' => $issued->expiresAt->toIso8601String(),
        ];
        $challenge->forceFill(['payload' => $payload])->save();
    }

    public function context(Challenge $challenge, ?TenantId $requestedTenant = null): ?AuthenticationRequestContext
    {
        if (config('tenancy.enabled') !== true) {
            return null;
        }

        $payload = is_array($challenge->payload) ? $challenge->payload : [];
        $state = $payload[self::PAYLOAD_KEY] ?? null;
        if (! is_array($state)) {
            return null;
        }
        $nonce = $state['nonce'] ?? null;
        $purpose = $state['purpose'] ?? null;
        $provider = $state['provider'] ?? null;
        $subjectBound = $state['subject_bound'] ?? null;
        $tenantId = $state['tenant_id'] ?? null;
        $expiresAt = $state['expires_at'] ?? null;
        if (! is_string($nonce)
            || ! is_string($purpose)
            || ! is_string($provider)
            || ! is_bool($subjectBound)
            || ! is_string($tenantId)
            || ! is_string($expiresAt)) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }
        $tenantPurpose = TenantAuthenticationPurpose::tryFrom($purpose);
        if (! $tenantPurpose instanceof TenantAuthenticationPurpose) {
            throw new AuthException('tenant_authentication_intent_invalid', 'The tenant authentication intent is invalid.', 410);
        }

        return new AuthenticationRequestContext(
            tenantIntentNonce: $nonce,
            tenantSessionBinding: $this->session->authenticationFlowBinding($this->flow($provider, $challenge->identifier())),
            tenantPurpose: $tenantPurpose,
            tenantProvider: $provider,
            tenantIntentTenant: new TenantId($tenantId),
            tenantIntentExpiresAt: CarbonImmutable::parse($expiresAt),
            requestedTenant: $requestedTenant,
            tenantIntentSubjectBound: $subjectBound,
        );
    }

    private function flow(string $provider, string $challengeId): string
    {
        return "{$provider}:{$challengeId}";
    }
}

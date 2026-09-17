<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Data\Mutations\ApiTokenData;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Tenancy\Contracts\TenantContext;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\Enums\TenantContextMode;

/**
 * Enforces the host's API-token ability catalog.
 */
final readonly class ApiTokenPolicy
{
    /**
     * Create the API-token policy.
     */
    public function __construct(
        private ApiTokenAbilityProvider $abilities,
        private MembershipPrincipalResolver $principals,
        private TenantMembershipAccess $memberships,
        private TenantContext $context,
        private AuthOperationBoundary $operations,
    ) {}

    /**
     * Require every requested ability to be allowlisted for the subject.
     */
    public function authorize(Authenticatable $subject, ApiTokenData $data): void
    {
        $this->authorizeSubject($subject);
        $allowed = $this->abilities->abilities($subject);

        if (in_array('*', $allowed, true)) {
            return;
        }

        foreach ($data->abilities as $ability) {
            if (! in_array($ability, $allowed, true)) {
                throw new AuthException('api_token_ability_forbidden', 'An API token ability is not permitted.', 422);
            }
        }
    }

    /** Require a fresh eligible principal in the active tenant or explicit platform boundary. */
    public function authorizeSubject(Authenticatable $subject): void
    {
        if (config('tenancy.enabled') === true) {
            $this->principals->assertEligible($subject);
            $snapshot = $this->context->snapshot();
            if ($snapshot->mode === TenantContextMode::Tenant && $snapshot->tenantId !== null) {
                $this->memberships->assertMember($subject, $snapshot->tenantId);
            } elseif ($snapshot->mode === TenantContextMode::Platform) {
                $this->operations->requirePlatformAdministration();
            } else {
                throw new AuthException('tenant_context_required', 'A tenant or platform context is required.', 403);
            }
        }
    }
}

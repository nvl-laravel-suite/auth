<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\InvitationTenantBootstrap;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Tenancy\Services\TenantBoundary;
use Nvl\Tenancy\Services\TenantRunner;

/**
 * Resolves public, non-secret invitation context before host provisioning.
 */
final readonly class PreviewInvitationAction
{
    /**
     * Create the invitation preview use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private InvitationTenantBootstrap $bootstrap,
        private TenantRunner $runner,
        private TenantBoundary $boundary,
    ) {}

    /**
     * Resolve one active invitation by its bearer token.
     */
    public function execute(string $token): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
        if (config('tenancy.enabled') === true) {
            $tenant = $this->bootstrap->tenantForToken($token);
            if ($tenant === null) {
                throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
            }

            return $this->runner->run($tenant, function () use ($token): Invitation {
                /** @var Invitation|null $invitation */
                $invitation = $this->boundary->query(Invitation::query(), 'auth.invitations')
                    ->where('token_hash', $this->hasher->hash('invitation-token', $token))
                    ->first();
                if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
                    throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
                }

                return $invitation->makeHidden(['roles', 'permissions', 'metadata', 'tenant_id', 'ownership_key']);
            });
        }
        /** @var Invitation|null $invitation */
        $invitation = Invitation::query()
            ->where('token_hash', $this->hasher->hash('invitation-token', $token))
            ->first();

        if (! $invitation instanceof Invitation || ! $invitation->isUsable()) {
            throw new AuthException('invitation_invalid', 'The invitation is invalid or expired.', 410);
        }

        return $invitation;
    }
}

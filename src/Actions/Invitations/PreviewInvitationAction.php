<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\Invitations;

use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Invitation;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;

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
    ) {}

    /**
     * Resolve one active invitation by its bearer token.
     */
    public function execute(string $token): Invitation
    {
        $this->features->assertAllowed(AuthFeature::Invitations, FeatureOperation::Read);
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

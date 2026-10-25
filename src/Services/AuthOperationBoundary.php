<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/** Separates narrow central identity work from privileged platform administration. */
final readonly class AuthOperationBoundary
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private AuthModelRegistry $models, private OwnershipContext $ownership, private AuthOwnershipState $state) {}

    /** Native Auth operation. */
    public function central(AuthIdentityOperation $operation, ?Authenticatable $subject = null): void
    {
        $feature = match ($operation) {
            AuthIdentityOperation::Login, AuthIdentityOperation::Logout => AuthFeature::Authentication,
            AuthIdentityOperation::Recovery, AuthIdentityOperation::Password => AuthFeature::Password,
            AuthIdentityOperation::VerifyEmail => AuthFeature::EmailVerification,
            AuthIdentityOperation::Profile => AuthFeature::PrincipalManagement,
            AuthIdentityOperation::Mfa => AuthFeature::Totp,
            AuthIdentityOperation::SocialIdentity => AuthFeature::SocialIdentities,
            AuthIdentityOperation::MembershipDiscovery => AuthFeature::Memberships,
        };
        $this->features->assertAllowed($feature, FeatureOperation::Read);
        if ($subject === null) {
            return;
        }
        $class = $this->models->userClass();
        $model = new $class;
        $reference = SubjectReference::fromAuthenticatable($subject);
        if (! $subject instanceof Model || $reference->type !== $model->getMorphClass() || ! $class::query()->where($model->getKeyName(), $reference->identifier)->exists()) {
            throw new AuthException('subject_unavailable', 'The authenticated subject is unavailable.', 404);
        }
    }

    /** Native Auth operation. */
    public function requirePlatformAdministration(): void
    {
        if ($this->state->native()) {
            if ($this->ownership->snapshot()->mode !== OwnershipContextMode::Central) {
                throw new OwnershipViolation('Global Auth administration requires explicit central admission.');
            }

            return;
        }
    }

    /** Reject legacy RBAC entry points that mix platform and tenant-owned writes. */
    public function rejectMixedRbacOperation(): void
    {
        if ($this->state->configured()) {
            throw new AuthException('rbac_mixed_context_operation', 'This RBAC operation mixes platform and tenant-owned state.', 409);
        }
    }
}

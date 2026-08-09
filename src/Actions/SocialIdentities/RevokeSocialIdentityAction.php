<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Revokes one social identity link without touching provider-owned credentials.
 */
final readonly class RevokeSocialIdentityAction
{
    /**
     * Create the social identity revocation use case.
     */
    public function __construct(
        private FeatureGate $features,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Revoke an owned identity idempotently.
     */
    public function execute(
        Authenticatable $subject,
        SocialIdentity $identity,
    ): SocialIdentity {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);

        if ($identity->subject_type !== $reference->type
            || $identity->subject_id !== $reference->identifier) {
            throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
        }

        return DB::connection($identity->getConnectionName())->transaction(function () use ($identity, $reference, $subject): SocialIdentity {
            /** @var SocialIdentity $locked */
            $locked = SocialIdentity::query()->whereKey($identity->identifier())->lockForUpdate()->firstOrFail();

            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->audits->record(
                    'social_identity.revoked',
                    subject: $reference,
                    actor: $subject,
                    metadata: ['provider' => $locked->provider, 'social_identity_id' => $locked->identifier()],
                );
            }

            return $locked;
        }, 3);
    }
}

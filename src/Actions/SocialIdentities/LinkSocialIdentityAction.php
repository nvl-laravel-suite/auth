<?php

declare(strict_types=1);

namespace Nvl\Auth\Actions\SocialIdentities;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\FeatureGate;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Links verified external claims to one host-owned subject.
 */
final readonly class LinkSocialIdentityAction
{
    /**
     * Create the social identity linking use case.
     */
    public function __construct(
        private FeatureGate $features,
        private SecretHasher $hasher,
        private AuthAuditRecorder $audits,
    ) {}

    /**
     * Link or refresh one provider identity.
     */
    public function execute(
        Authenticatable $subject,
        ExternalIdentity $identity,
    ): SocialIdentity {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Enroll);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $providerUserHash = $this->hasher->hash(
            "social-identity-{$identity->provider}",
            $identity->providerUserId,
        );
        $connection = (new SocialIdentity)->getConnectionName();

        return DB::connection($connection)->transaction(function () use (
            $identity,
            $providerUserHash,
            $reference,
            $subject,
        ): SocialIdentity {
            /** @var SocialIdentity|null $existing */
            $existing = SocialIdentity::query()
                ->where('provider', $identity->provider)
                ->where('provider_user_id_hash', $providerUserHash)
                ->lockForUpdate()
                ->first();

            if ($existing instanceof SocialIdentity
                && ($existing->subject_type !== $reference->type
                    || $existing->subject_id !== $reference->identifier)) {
                throw new AuthException('social_identity_conflict', 'The social identity is already linked.', 409);
            }

            $record = $existing ?? new SocialIdentity;
            $record->fill([
                'subject_type' => $reference->type,
                'subject_id' => $reference->identifier,
                'provider' => $identity->provider,
                'provider_user_id' => $identity->providerUserId,
                'provider_user_id_hash' => $providerUserHash,
                'email' => $identity->email,
                'profile' => [
                    'name' => $identity->name,
                    'avatar' => $identity->avatar,
                    ...$identity->profile,
                ],
                'last_used_at' => now(),
                'revoked_at' => null,
            ])->save();
            $this->audits->record(
                'social_identity.linked',
                subject: $reference,
                actor: $subject,
                metadata: ['provider' => $identity->provider, 'social_identity_id' => $record->identifier()],
            );

            return $record;
        }, 3);
    }
}

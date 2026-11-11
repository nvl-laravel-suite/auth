<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AccountAuthenticationPolicy;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Enums\SocialIntentPurpose;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\IssuedSocialIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Events\DomainEventDispatcher;

/**
 * Explicit recent-proof-before-redirect account link and reconnect operations.
 *
 * @api
 */
final readonly class AuthSocialLinks
{
    public function __construct(private SocialAuthenticationIntents $intents, private SecretHasher $hasher, private PrincipalSecurity $security, private AuthAuditRecorder $audits, private AuthConfiguration $configuration, private AuthPipeline $pipeline, private RecentAuthenticationProofs $recent, private FeatureGate $features, private UsableAccountAuthenticationPolicy $nativeRemoval, private AccountAuthenticationPolicy $removalPolicy, private DomainEventDispatcher $securityEvents) {}

    /** @return array{url: string, intent: IssuedSocialIntent} */
    public function beginLink(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): array
    {
        return $this->intents->begin($provider, SocialIntentPurpose::Link, $context, AuthenticationDestination::Session, $subject, $recentProof);
    }

    public function completeLink(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context): SocialIdentity
    {
        return $this->complete($subject, $provider, $intent, $context, SocialIntentPurpose::Link);
    }

    /** @return array{url: string, intent: IssuedSocialIntent} */
    public function beginReconnect(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): array
    {
        return $this->intents->begin($provider, SocialIntentPurpose::Reconnect, $context, AuthenticationDestination::Session, $subject, $recentProof);
    }

    public function completeReconnect(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context): SocialIdentity
    {
        return $this->complete($subject, $provider, $intent, $context, SocialIntentPurpose::Reconnect);
    }

    public function unlink(Authenticatable $subject, string $identityId, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Revoke);
        $this->recent->assertValid($subject, $recentProof, RecentAuthenticationPurpose::SocialUnlink, $context);

        return (new SocialIdentity)->getConnection()->transaction(function () use ($subject, $identityId, $recentProof, $context): SocialIdentity {
            $this->recent->consume($subject, $recentProof, RecentAuthenticationPurpose::SocialUnlink, $context);
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $link = SocialIdentity::query()->whereKey($identityId)->lockForUpdate()->first();
            if ($link === null || $link->subject_type !== $reference->type || $link->subject_id !== $reference->identifier) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 422);
            }
            if ($link->revoked_at === null) {
                $this->nativeRemoval->assertRemovalAllowed($subject, 'social', $identityId);
                $this->removalPolicy->assertRemovalAllowed($subject, 'social', $identityId);
                $this->nativeRemoval->assertRemovalAllowed($subject, 'social', $identityId);
                $link->update(['revoked_at' => now()]);
                $this->security->advance($subject, 'social_revoked', $context);
                $this->audits->record('social_identity.revoked', subject: $reference, actor: $subject, metadata: ['social_identity_id' => $identityId]);
                $this->securityEvents->dispatch(new AccountSecurityChanged($reference, 'social_identity_revoked', $identityId), (new SocialIdentity)->getConnection());
            }

            return $link;
        });
    }

    private function complete(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context, SocialIntentPurpose $purpose): SocialIdentity
    {
        return $this->intents->complete($provider, $intent, $purpose, $context, $subject, function (ExternalIdentity $identity, ?Authenticatable $canonical) use ($context, $purpose): SocialIdentity {
            if ($canonical === null) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 422);
            }
            $reference = SubjectReference::fromAuthenticatable($canonical);

            return $this->pipeline->run('social_link_change', new AuthPipelineContext('social_link_change', ['operation' => $purpose->value, 'provider' => $identity->provider], $reference), function () use ($canonical, $identity, $reference, $purpose, $context): SocialIdentity {
                $this->security->lock($canonical);
                $this->security->lockChallenges($canonical);
                $hash = $this->hasher->hash("social-identity-{$identity->provider}", $identity->providerUserId);
                $link = SocialIdentity::query()->where('provider', $identity->provider)->where('provider_user_id_hash', $hash)->lockForUpdate()->first();
                if ($link !== null && ($link->subject_type !== $reference->type || $link->subject_id !== $reference->identifier || ($link->profile['issuer'] ?? null) !== $identity->issuer)
                    || $purpose === SocialIntentPurpose::Link && $link?->revoked_at !== null || $purpose === SocialIntentPurpose::Reconnect && $link === null) {
                    throw new AuthException('social_identity_conflict', 'The social identity is unavailable for this operation.', 409);
                }
                $link ??= new SocialIdentity;
                $link->fill(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'provider' => $identity->provider, 'provider_user_id' => $identity->providerUserId, 'provider_user_id_hash' => $hash, 'email' => $identity->email, 'profile' => ['name' => $identity->name, 'avatar' => $identity->avatar, 'issuer' => $identity->issuer, 'email_verified' => $identity->emailVerified, 'email_verification_source' => $identity->emailVerificationSource, 'connection_realm' => $this->configuration->get("features.social_identities.settings.providers.{$identity->provider}.realm")], 'last_used_at' => now(), 'revoked_at' => null])->save();
                $this->security->advance($canonical, 'social_linked', $context);
                $this->audits->record($purpose === SocialIntentPurpose::Link ? 'social_identity.linked' : 'social_identity.reconnected', subject: $reference, actor: $canonical, metadata: ['provider' => $identity->provider, 'social_identity_id' => $link->identifier()]);

                return $link;
            });
        });
    }
}

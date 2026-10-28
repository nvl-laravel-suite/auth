<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Enums\SocialIntentPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\IssuedSocialIntent;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/** Native callback verification and one-use accounting shared by complete social operations. @internal */
final readonly class SocialAuthenticationIntents
{
    public function __construct(private FeatureGate $features, private SocialProviderRegistry $registry, private SocialProviderConfiguration $configuration, private AuthConfiguration $settings, private SocialIdentityProviderFactory $factory, private AuthIdentityChallenges $records, private SecretHasher $hasher, private PrincipalSecurity $security, private RecentAuthenticationProofs $recent, private CanonicalActorResolver $canonical, private AuthSubjectResolver $subjects, private PrincipalEligibility $eligibility) {}

    /** @return array{url: string, intent: IssuedSocialIntent} */
    public function begin(string $provider, SocialIntentPurpose $purpose, AuthenticationRequestContext $context, AuthenticationDestination $destination, ?Authenticatable $subject = null, #[\SensitiveParameter] ?string $recentProof = null): array
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Issue);
        $context->assertBound($destination);
        $this->assertExternalBoundary();
        if ((new SocialIdentity)->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Social identity and intent storage require one source.');
        }
        $this->registry->assertAvailable($provider);
        $subject = $subject === null ? null : $this->canonical->resolve($subject);
        $record = (new Challenge)->getConnection()->transaction(function () use ($provider, $purpose, $context, $destination, $subject, $recentProof): array {
            $revision = null;
            if ($subject !== null) {
                $revision = $this->security->lock($subject)->revision;
                if ($purpose === SocialIntentPurpose::Link || $purpose === SocialIntentPurpose::Reconnect) {
                    $this->recent->consume($subject, $recentProof, $purpose === SocialIntentPurpose::Link ? RecentAuthenticationPurpose::SocialLink : RecentAuthenticationPurpose::SocialReconnect, $context);
                }
            }
            $reference = $subject === null ? null : SubjectReference::fromAuthenticatable($subject);
            $secret = bin2hex(random_bytes(32));
            $expiry = CarbonImmutable::now('UTC')->addSeconds(300);
            $this->records->create(['type' => 'social_intent', 'purpose' => $purpose->value, 'subject_type' => $reference?->type, 'subject_id' => $reference?->identifier, 'secret_hash' => $this->hasher->hash('native-social-purpose-intent', $secret), 'payload' => ['provider' => $provider, 'destination' => $destination->value, 'context' => $context->facts(), 'revision' => $revision, 'connection' => $this->fingerprint($provider)], 'max_attempts' => 1, 'expires_at' => $expiry]);

            return ['secret' => $secret, 'expiry' => $expiry];
        });
        $configuration = $this->configuration->provider($provider);
        try {
            $url = $this->factory->make($provider)->redirectUrl($provider, $configuration['callback_url'], $configuration['scopes'], $configuration['parameters']);
        } catch (\Throwable) {
            throw new AuthException('social_provider_unavailable', 'The social provider is unavailable.', 422);
        }
        $parts = parse_url($url);
        if (strlen($url) > 8192 || filter_var($url, FILTER_VALIDATE_URL) === false || ! is_array($parts) || ! in_array($parts['scheme'] ?? null, ['https', 'http'], true) || isset($parts['user']) || isset($parts['pass']) || preg_match('/[\x00-\x1F\x7F]/', $url)) {
            throw AuthException::invalidConfiguration('Invalid social redirect.');
        }

        return ['url' => $url, 'intent' => new IssuedSocialIntent($record['secret'], $record['expiry'])];
    }

    /** SDK verification runs outside locks; terminal runs inside the canonical mutation transaction.
     * @template TResult
     *
     * @param  Closure(ExternalIdentity, ?Authenticatable, Challenge): TResult  $terminal
     * @return TResult
     */
    public function complete(string $provider, #[\SensitiveParameter] string $secret, SocialIntentPurpose $purpose, AuthenticationRequestContext $context, ?Authenticatable $subject, Closure $terminal): mixed
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $this->assertExternalBoundary();
        $snapshot = $this->intent($provider, $secret, $purpose, $context, $subject, false);
        $this->registry->assertAvailable($provider);
        $configuration = $this->configuration->provider($provider);
        try {
            $identity = $this->factory->make($provider)->user($provider, $configuration['callback_url']);
        } catch (\Throwable) {
            throw new AuthException('social_authorization_failed', 'The social authorization could not be completed. Restart authorization.', 422);
        }
        $issuer = $this->settings->get("features.social_identities.settings.providers.{$provider}.issuer");
        if ($identity->provider !== $provider || $issuer !== null && $identity->issuer !== $issuer) {
            throw $this->invalid();
        }
        $linked = SocialIdentity::query()->where('provider', $provider)->where('provider_user_id_hash', $this->hasher->hash("social-identity-{$provider}", $identity->providerUserId))->first();
        if ($subject === null && $linked !== null) {
            $subject = $this->subjects->resolve(new SubjectReference($linked->subject_type, $linked->subject_id));
            if ($subject === null) {
                throw $this->invalid();
            }
        }
        $resolved = $subject === null ? null : $this->canonical->resolve($subject);
        if ($resolved instanceof Model && $resolved->getConnection() !== $snapshot->getConnection()) {
            throw AuthException::invalidConfiguration('Social operations require one canonical source.');
        }

        return $snapshot->getConnection()->transaction(function () use ($provider, $secret, $purpose, $context, $subject, $resolved, $terminal, $identity): mixed {
            if ($resolved !== null) {
                $revision = $this->security->lock($resolved)->revision;
                $this->security->lockChallenges($resolved);
                $this->eligibility->assertEligible($resolved, AuthenticationPurpose::SocialLogin);
            }
            $intent = $this->intent($provider, $secret, $purpose, $context, $purpose === SocialIntentPurpose::Login ? null : $subject, true);
            if ($resolved !== null && $intent->subject_id !== null && ($intent->payload['revision'] ?? null) !== $revision) {
                throw $this->invalid();
            }
            $intent->consumed_at = CarbonImmutable::now('UTC');
            $this->records->save($intent);

            return $terminal($identity, $resolved, $intent);
        }, 3);
    }

    private function intent(string $provider, #[\SensitiveParameter] string $secret, SocialIntentPurpose $purpose, AuthenticationRequestContext $context, ?Authenticatable $subject, bool $lock): Challenge
    {
        if (preg_match('/\A[0-9a-f]{64}\z/', $secret) !== 1) {
            throw $this->invalid();
        }
        $query = $this->records->query()->where('type', 'social_intent')->where('secret_hash', $this->hasher->hash('native-social-purpose-intent', $secret));
        $intent = ($lock ? $query->lockForUpdate() : $query)->first();
        $reference = $subject === null ? null : SubjectReference::fromAuthenticatable($subject);
        if (! $intent instanceof Challenge || ! $intent->isUsable() || $intent->purpose !== $purpose->value || $intent->subject_type !== $reference?->type || $intent->subject_id !== $reference?->identifier || ($intent->payload['provider'] ?? null) !== $provider || ($intent->payload['context'] ?? null) !== $context->facts() || ($intent->payload['connection'] ?? null) !== $this->fingerprint($provider)) {
            throw $this->invalid();
        }

        return $intent;
    }

    private function assertExternalBoundary(): void
    {
        if ((new Challenge)->getConnection()->transactionLevel() !== 0) {
            throw new AuthException('social_transaction_unsupported', 'Complete social authorization outside an enclosing transaction.', 422);
        }
    }

    private function fingerprint(string $provider): string
    {
        return hash('sha256', json_encode($this->settings->get("features.social_identities.settings.providers.{$provider}"), JSON_THROW_ON_ERROR));
    }

    private function invalid(): AuthException
    {
        return new AuthException('social_intent_invalid', 'The social authorization intent is invalid or expired.', 422);
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Complete native AuthSocialIdentities operations.
 *
 * @api
 */
final readonly class AuthSocialIdentities
{
    use IssuesAuthenticationProofs;

    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private SocialProviderConfiguration $configuration, private SocialIdentityProviderFactory $providerFactory, private AuthOperationBoundary $operations, private SocialSubjectResolver $subjects, private AuthSubjectResolver $authSubjects, private AuthAuditRecorder $audits, private SecretHasher $hasher, private PrincipalSecurity $security, private AuthIdentityChallenges $records, private RecentAuthenticationProofs $recent) {}

    /** Begin a browser-bound native social authentication, retaining SDK-owned OAuth state.
     * @return array{url: string, intent: IssuedAuthenticationProof}
     */
    public function startAuthentication(string $provider, AuthenticationRequestContext $context): array
    {
        $context->assertBound(AuthenticationDestination::Session);
        $url = $this->startAuthorization($provider);
        $secret = bin2hex(random_bytes(32));
        $this->records->create(['type' => 'social_authentication', 'purpose' => 'social_login', 'secret_hash' => $this->hasher->hash('native-social-intent', $secret),
            'payload' => ['provider' => $provider, 'destination' => AuthenticationDestination::Session->value, 'context' => $context->facts()], 'max_attempts' => 1, 'expires_at' => CarbonImmutable::now('UTC')->addSeconds(300)]);

        return ['url' => $url, 'intent' => new IssuedAuthenticationProof($secret)];
    }

    /** Acquire fresh provider claims only through a matching native browser intent. */
    public function finishAuthentication(string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::SocialIdentity);
        $context->assertBound(AuthenticationDestination::Session);
        $snapshot = $this->records->query()->where('type', 'social_authentication')->where('secret_hash', $this->hasher->hash('native-social-intent', $intent))->first();
        $facts = ['provider' => $provider, 'destination' => AuthenticationDestination::Session->value, 'context' => $context->facts()];
        if (! $snapshot instanceof Challenge || ! $snapshot->isUsable() || $snapshot->payload !== $facts) {
            throw new AuthException('authentication_proof_invalid', 'The social authentication intent is invalid or expired.', 422);
        }
        $identity = $this->verifiedExternalIdentity($provider);
        $subject = $this->authorizationSubject($identity);
        if (! $subject instanceof Model || $subject->getConnection() !== $snapshot->getConnection()) {
            throw AuthException::invalidConfiguration('Social authentication requires one canonical source.');
        }
        $revision = $this->security->revisionSnapshot($subject);

        return $subject->getConnection()->transaction(function () use ($subject, $identity, $provider, $snapshot, $facts, $context, $revision): IssuedAuthenticationProof {
            $state = $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            $challenge = $this->records->query()->whereKey($snapshot->identifier())->where('type', 'social_authentication')->lockForUpdate()->first();
            if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->payload !== $facts || $state->revision !== $revision) {
                throw new AuthException('authentication_proof_invalid', 'The social authentication intent is invalid or expired.', 422);
            }
            $hash = $this->hasher->hash("social-identity-{$provider}", $identity->providerUserId);
            $existing = SocialIdentity::query()->where('provider', $provider)->where('provider_user_id_hash', $hash)->lockForUpdate()->first();
            $challenge->consumed_at = CarbonImmutable::now('UTC');
            $this->records->save($challenge);
            $linked = $this->persistIdentity($subject, $identity);
            $fresh = SocialIdentity::query()->whereKey($linked->identifier())->lockForUpdate()->first();
            $expectedRevision = $revision + ($existing === null ? 1 : 0);
            $reference = SubjectReference::fromAuthenticatable($subject);
            if (! $fresh instanceof SocialIdentity || $fresh->revoked_at !== null || $fresh->subject_type !== $reference->type || $fresh->subject_id !== $reference->identifier
                || $fresh->provider !== $provider || $fresh->provider_user_id_hash !== $hash || ($fresh->profile['issuer'] ?? null) !== $identity->issuer
                || $this->security->lock($subject)->revision !== $expectedRevision) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
            }

            return $this->issueNativeProof($subject, AuthenticationMethod::Social, AuthenticationDestination::Session, $context, $expectedRevision, provider: $provider);
        });
    }

    /**
     * Return the provider redirect URL.
     */
    public function startAuthorization(string $provider): string
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Issue);
        $this->operations->central(AuthIdentityOperation::SocialIdentity);
        $configuration = $this->configuration->provider($provider);
        try {
            $url = $this->providerFactory->make($provider)->redirectUrl($provider, $configuration['callback_url'], $configuration['scopes'], $configuration['parameters']);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException('social_provider_unavailable', 'The social authorization provider is unavailable.', 502, previous: $exception);
        }
        $parts = parse_url($url);
        if (mb_strlen($url) > 8192 || filter_var($url, FILTER_VALIDATE_URL) === false || ! is_array($parts) || ! in_array(strtolower((string) ($parts['scheme'] ?? '')), ['http', 'https'], true) || ! is_string($parts['host'] ?? null) || isset($parts['user']) || isset($parts['pass']) || preg_match('/[\x00-\x1F\x7F]/', $url) === 1) {
            throw AuthException::invalidConfiguration('The social identity provider returned an invalid redirect URL.');
        }

        return $url;
    }

    /**
     * Acquire provider claims and link them to a supplied or resolved host subject.
     */
    public function completeAuthorization(string $provider, Authenticatable $subject, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::SocialIdentity, $subject);
        $identity = $this->verifiedExternalIdentity($provider);

        return $this->link($this->authorizationSubject($identity, $subject), $identity, $grant, $context);
    }

    /** Network verification precedes native row locks, including inside a host transaction. */
    private function verifiedExternalIdentity(string $provider): ExternalIdentity
    {
        $configuration = $this->configuration->provider($provider);
        try {
            $identity = $this->providerFactory->make($provider)->user($provider, $configuration['callback_url']);
        } catch (AuthException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new AuthException('social_authorization_failed', 'The social authorization could not be completed.', 422, previous: $exception);
        }
        if ($identity->provider !== $provider) {
            throw AuthException::invalidConfiguration('The social identity belongs to a different provider.');
        }

        return $identity;
    }

    /** Preserve existing host identity resolution while native finalizers retain proof provenance. */
    private function authorizationSubject(ExternalIdentity $identity, ?Authenticatable $subject = null): Authenticatable
    {
        if ($subject !== null) {
            return $subject;
        }
        $hash = $this->hasher->hash("social-identity-{$identity->provider}", $identity->providerUserId);
        $existing = SocialIdentity::query()->where('provider', $identity->provider)->where('provider_user_id_hash', $hash)->first();
        if ($existing instanceof SocialIdentity) {
            if ($existing->revoked_at !== null) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
            }
            $linkedSubject = $this->authSubjects->resolve(new SubjectReference($existing->subject_type, $existing->subject_id));
            if ($linkedSubject === null) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
            }

            return $linkedSubject;
        }
        if ($identity->email === null || trim($identity->email) === '' || ! $identity->emailVerified) {
            throw new AuthException('social_email_unverified', 'The social provider did not prove the returned email address.', 422);
        }

        return $this->subjects->resolve($identity);
    }

    /**
     * Link or refresh one provider identity.
     */
    public function link(Authenticatable $subject, ExternalIdentity $identity, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): SocialIdentity
    {
        $reference = SubjectReference::fromAuthenticatable($subject);
        $existing = SocialIdentity::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('provider', $identity->provider)->where('provider_user_id_hash', $this->hasher->hash("social-identity-{$identity->provider}", $identity->providerUserId))->exists();
        $purpose = $existing ? RecentAuthenticationPurpose::SocialReconnect : RecentAuthenticationPurpose::SocialLink;
        $this->recent->assertValid($subject, $grant, $purpose, $context);

        return (new SocialIdentity)->getConnection()->transaction(function () use ($subject, $identity, $grant, $purpose, $context): SocialIdentity {
            $this->recent->consume($subject, $grant, $purpose, $context);

            return $this->persistIdentity($subject, $identity);
        });
    }

    private function persistIdentity(Authenticatable $subject, ExternalIdentity $identity): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Enroll);
        $this->operations->central(AuthIdentityOperation::SocialIdentity, $subject);
        $reference = SubjectReference::fromAuthenticatable($subject);
        $providerUserHash = $this->hasher->hash("social-identity-{$identity->provider}", $identity->providerUserId);
        $connection = (new SocialIdentity)->getConnectionName();

        return DB::connection($connection)->transaction(function () use ($identity, $providerUserHash, $reference, $subject): SocialIdentity {
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            /** @var SocialIdentity|null $existing */
            $existing = SocialIdentity::query()->where('provider', $identity->provider)->where('provider_user_id_hash', $providerUserHash)->lockForUpdate()->first();
            if ($existing instanceof SocialIdentity && $existing->revoked_at !== null) {
                throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
            }
            if ($existing instanceof SocialIdentity && ($existing->subject_type !== $reference->type || $existing->subject_id !== $reference->identifier)) {
                throw new AuthException('social_identity_conflict', 'The social identity is already linked.', 409);
            }
            if ($existing instanceof SocialIdentity && ($existing->profile['issuer'] ?? null) !== $identity->issuer) {
                throw new AuthException('social_identity_conflict', 'The social identity issuer does not match the existing link.', 409);
            }
            $record = $existing ?? new SocialIdentity;
            $record->fill(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'provider' => $identity->provider, 'provider_user_id' => $identity->providerUserId, 'provider_user_id_hash' => $providerUserHash, 'email' => $identity->email, 'profile' => ['name' => $identity->name, 'avatar' => $identity->avatar, ...$identity->profile, 'email_verified' => $identity->emailVerified, 'email_verification_source' => $identity->emailVerificationSource, 'issuer' => $identity->issuer], 'last_used_at' => now()])->save();
            if ($existing === null) {
                $this->security->advance($subject, 'social_linked');
            }
            $this->audits->record('social_identity.linked', subject: $reference, actor: $subject, metadata: ['provider' => $identity->provider, 'social_identity_id' => $record->identifier()]);

            return $record;
        }, 3);
    }

    /**
     * Revoke an owned identity idempotently.
     */
    public function revoke(Authenticatable $subject, SocialIdentity $identity, #[\SensitiveParameter] ?string $grant = null, ?AuthenticationRequestContext $context = null): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Revoke);
        $this->recent->assertValid($subject, $grant, RecentAuthenticationPurpose::SocialUnlink, $context);
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($identity->subject_type !== $reference->type || $identity->subject_id !== $reference->identifier) {
            throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
        }

        if ($identity->getConnection() !== (new SocialIdentity)->getConnection()) {
            throw AuthException::invalidConfiguration('Credential mutations require the canonical source connection.');
        }

        return DB::connection($identity->getConnectionName())->transaction(function () use ($identity, $reference, $subject, $grant, $context): SocialIdentity {
            $this->recent->consume($subject, $grant, RecentAuthenticationPurpose::SocialUnlink, $context);
            $this->security->lock($subject);
            $this->security->lockChallenges($subject);
            /** @var SocialIdentity $locked */
            $locked = SocialIdentity::query()->whereKey($identity->identifier())->lockForUpdate()->firstOrFail();
            if ($locked->revoked_at === null) {
                $locked->forceFill(['revoked_at' => CarbonImmutable::now()])->save();
                $this->security->advance($subject, 'social_revoked');
                $this->audits->record('social_identity.revoked', subject: $reference, actor: $subject, metadata: ['provider' => $locked->provider, 'social_identity_id' => $locked->identifier()]);
            }

            return $locked;
        }, 3);
    }
}

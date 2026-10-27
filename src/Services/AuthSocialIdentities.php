<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Contracts\SocialSubjectResolver;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthIdentityOperation;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\SubjectReference;
use Throwable;

/**
 * Complete native AuthSocialIdentities operations.
 *
 * @api
 */
final readonly class AuthSocialIdentities
{
    /** Native Auth operation. */
    public function __construct(private FeatureGate $features, private SocialProviderConfiguration $configuration, private SocialIdentityProviderFactory $providerFactory, private AuthOperationBoundary $operations, private SocialSubjectResolver $subjects, private AuthSubjectResolver $authSubjects, private AuthAuditRecorder $audits, private SecretHasher $hasher, private PrincipalSecurity $security) {}

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
    public function completeAuthorization(string $provider, ?Authenticatable $subject = null): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Use);
        $this->operations->central(AuthIdentityOperation::SocialIdentity, $subject);
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
        if ($subject === null) {
            $hash = $this->hasher->hash("social-identity-{$provider}", $identity->providerUserId);
            $existing = SocialIdentity::query()->where('provider', $provider)->where('provider_user_id_hash', $hash)->first();
            if ($existing instanceof SocialIdentity) {
                if ($existing->revoked_at !== null) {
                    throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
                }
                $linkedSubject = $this->authSubjects->resolve(new SubjectReference($existing->subject_type, $existing->subject_id));
                if ($linkedSubject === null) {
                    throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
                }

                return $this->link($linkedSubject, $identity);
            }
            if ($identity->email === null || trim($identity->email) === '' || ! $identity->emailVerified) {
                throw new AuthException('social_email_unverified', 'The social provider did not prove the returned email address.', 422);
            }
        }
        $resolvedSubject = $subject ?? $this->subjects->resolve($identity);
        $record = $this->link($resolvedSubject, $identity);

        return $record;
    }

    /**
     * Link or refresh one provider identity.
     */
    public function link(Authenticatable $subject, ExternalIdentity $identity): SocialIdentity
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
    public function revoke(Authenticatable $subject, SocialIdentity $identity): SocialIdentity
    {
        $this->features->assertAllowed(AuthFeature::SocialIdentities, FeatureOperation::Revoke);
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($identity->subject_type !== $reference->type || $identity->subject_id !== $reference->identifier) {
            throw new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 404);
        }

        if ($identity->getConnection() !== (new SocialIdentity)->getConnection()) {
            throw AuthException::invalidConfiguration('Credential mutations require the canonical source connection.');
        }

        return DB::connection($identity->getConnectionName())->transaction(function () use ($identity, $reference, $subject): SocialIdentity {
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

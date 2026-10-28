<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\SocialIntentPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\ExternalIdentity;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\IssuedSocialIntent;
use Nvl\Auth\ValueObjects\IssuedSocialRegistration;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Complete purpose-bound social login and existing-link reauthentication.
 *
 * @api
 */
final readonly class AuthSocialAuthentication
{
    use IssuesAuthenticationProofs;

    public function __construct(private SocialAuthenticationIntents $intents, private AuthIdentityChallenges $records, private SecretHasher $hasher, private PrincipalSecurity $security, private SocialProviderRegistry $registry) {}

    /** @return array{url: string, intent: IssuedSocialIntent} */
    public function beginLogin(string $provider, AuthenticationRequestContext $context, AuthenticationDestination $destination = AuthenticationDestination::Session): array
    {
        if ($destination === AuthenticationDestination::Reauthentication) {
            throw new \InvalidArgumentException('Use subject-bound reauthentication.');
        }

        return $this->intents->begin($provider, SocialIntentPurpose::Login, $context, $destination);
    }

    /** @return array{status: 'authenticated', subject: Authenticatable, proof: IssuedAuthenticationProof}|array{status: 'registration_required', continuation: IssuedSocialRegistration} */
    public function completeLogin(string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context): array
    {
        return $this->intents->complete($provider, $intent, SocialIntentPurpose::Login, $context, null, function (ExternalIdentity $identity, ?Authenticatable $subject, Challenge $intent) use ($context): array {
            $link = $this->link($identity);
            if ($link === null) {
                $secret = bin2hex(random_bytes(32));
                $expiry = CarbonImmutable::now('UTC')->addSeconds(300);
                $this->records->create(['type' => 'social_registration', 'purpose' => SocialIntentPurpose::Registration->value, 'secret_hash' => $this->hasher->hash('native-social-registration', $secret), 'payload' => ['connection' => $intent->payload['connection'] ?? null, 'context' => $context->facts(), 'claims' => ['provider' => $identity->provider, 'id' => $identity->providerUserId, 'email' => $identity->email, 'emailVerified' => $identity->emailVerified, 'source' => $identity->emailVerificationSource, 'name' => $identity->name, 'avatar' => $identity->avatar, 'issuer' => $identity->issuer]], 'max_attempts' => 5, 'expires_at' => $expiry]);

                return ['status' => 'registration_required', 'continuation' => new IssuedSocialRegistration($secret, $expiry)];
            }
            if ($subject === null) {
                throw $this->unavailable();
            }
            $this->assertLinked($link, $subject, $identity);
            $link->update(['last_used_at' => now()]);

            return ['status' => 'authenticated', 'subject' => $subject, 'proof' => $this->issueNativeProof($subject, AuthenticationMethod::Social, ($context->tokenNamespace === null ? AuthenticationDestination::Session : AuthenticationDestination::ApiToken), $context, $this->security->lock($subject)->revision, provider: $identity->provider)];
        });
    }

    /** @return array{url: string, intent: IssuedSocialIntent} */
    public function beginReauthentication(Authenticatable $subject, string $provider, AuthenticationRequestContext $context): array
    {
        if (! ($this->registry->providers()[$provider]['supportsReauthentication'] ?? false)) {
            throw $this->unavailable();
        }

        return $this->intents->begin($provider, SocialIntentPurpose::Reauthentication, $context, AuthenticationDestination::Reauthentication, $subject);
    }

    public function completeReauthentication(Authenticatable $subject, string $provider, #[\SensitiveParameter] string $intent, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        return $this->intents->complete($provider, $intent, SocialIntentPurpose::Reauthentication, $context, $subject, function (ExternalIdentity $identity, ?Authenticatable $canonical) use ($context): IssuedAuthenticationProof {
            $link = $this->link($identity);
            if ($link === null || $canonical === null) {
                throw $this->unavailable();
            }
            $this->assertLinked($link, $canonical, $identity);

            return $this->issueNativeProof($canonical, AuthenticationMethod::Social, AuthenticationDestination::Reauthentication, $context, $this->security->lock($canonical)->revision, provider: $identity->provider);
        });
    }

    private function link(ExternalIdentity $identity): ?SocialIdentity
    {
        return SocialIdentity::query()->where('provider', $identity->provider)->where('provider_user_id_hash', $this->hasher->hash("social-identity-{$identity->provider}", $identity->providerUserId))->lockForUpdate()->first();
    }

    private function assertLinked(SocialIdentity $link, Authenticatable $subject, ExternalIdentity $identity): void
    {
        $reference = SubjectReference::fromAuthenticatable($subject);
        if ($link->revoked_at !== null || $link->subject_type !== $reference->type || $link->subject_id !== $reference->identifier || ($link->profile['issuer'] ?? null) !== $identity->issuer) {
            throw $this->unavailable();
        }
    }

    private function unavailable(): AuthException
    {
        return new AuthException('social_identity_unavailable', 'The social identity is unavailable.', 422);
    }
}

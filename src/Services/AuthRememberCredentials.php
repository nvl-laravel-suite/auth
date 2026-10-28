<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Traits\IssuesAuthenticationProofs;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/** Consumes a native remembered primary credential; enrolled MFA is still required by finalization. @api */
final readonly class AuthRememberCredentials
{
    use IssuesAuthenticationProofs;

    public function __construct(private FeatureGate $features, private SecretHasher $hasher, private PrincipalSecurity $security, private AuthIdentityChallenges $records, private AuthSubjectResolver $subjects, private CanonicalActorResolver $canonical, private PrincipalEligibility $eligibility) {}

    public function resume(string $selector, #[\SensitiveParameter] string $secret, string $guardName, AuthenticationRequestContext $context): IssuedAuthenticationProof
    {
        $this->features->assertAllowed(AuthFeature::ManagedSessions, FeatureOperation::Use);
        $context->assertBound(AuthenticationDestination::Session);
        if ($context->guardName !== $guardName || preg_match('/\A[0-9a-f]{64}\z/', $selector) !== 1 || preg_match('/\A[0-9a-f]{64}\z/', $secret) !== 1) {
            throw $this->invalid();
        }
        $snapshot = RememberCredential::query()->where('selector', $selector)->first();
        if ($snapshot === null) {
            throw $this->invalid();
        }
        $candidate = $this->subjects->resolve(new SubjectReference($snapshot->subject_type, $snapshot->subject_id));
        if ($candidate === null) {
            throw $this->invalid();
        }
        $subject = $this->canonical->resolve($candidate);
        if (! $subject instanceof Model || $subject->getConnection() !== $snapshot->getConnection() || $subject->getConnection() !== (new Challenge)->getConnection()) {
            throw AuthException::invalidConfiguration('Remember credentials require one canonical source.');
        }

        return $subject->getConnection()->transaction(function () use ($subject, $snapshot, $selector, $secret, $guardName, $context): IssuedAuthenticationProof {
            $revision = $this->security->lock($subject)->revision;
            $this->security->lockChallenges($subject);
            $subject = $this->canonical->resolve($subject, true);
            $this->eligibility->assertEligible($subject, AuthenticationMethod::Remember->purpose());
            $record = RememberCredential::query()->whereKey($snapshot->identifier())->where('selector', $selector)->lockForUpdate()->first();
            $reference = SubjectReference::fromAuthenticatable($subject);
            if ($record === null || $record->subject_type !== $reference->type || $record->subject_id !== $reference->identifier || $record->guard_name !== $guardName || $record->provider_hash !== AuthBrowserSessions::providerFingerprint($guardName) || $record->security_revision !== $revision || ! $record->absolute_expires_at->isFuture() || $record->consumed_at !== null || $record->revoked_at !== null || $record->rotated_to_id !== null || ! hash_equals($record->secret_hash, $this->hasher->hash('native-remember-secret', $secret))) {
                throw $this->invalid();
            }
            $record->consumed_at = CarbonImmutable::now('UTC');
            $record->save();

            return $this->issueNativeProof($subject, AuthenticationMethod::Remember, AuthenticationDestination::Session, $context, $revision, provider: $record->identifier());
        }, 3);
    }

    private function invalid(): AuthException
    {
        return new AuthException('remember_credential_invalid', 'The remembered credential is unavailable or expired.', 401);
    }
}

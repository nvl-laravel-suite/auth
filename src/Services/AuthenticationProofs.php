<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthenticationAssurancePolicy;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthenticationVerification;
use Nvl\Auth\ValueObjects\IssuedAuthenticationProof;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use Throwable;

/**
 * Consumes native persisted verification; exposes no caller-asserted issuance API.
 *
 * @api
 */
final readonly class AuthenticationProofs
{
    public function __construct(private AuthIdentityChallenges $records, private PrincipalSecurity $security, private SecretHasher $hasher, private AuthSubjectResolver $subjects, private AuthenticationEligibility $eligibility, private EnrolledFactorAssurancePolicy $enrollment, private AuthenticationAssurancePolicy $assurance, private AuthSecondFactor $secondFactor, private CanonicalActorResolver $actors, private PrincipalEligibility $nativeEligibility, private AuthAuditRecorder $audits) {}

    /** @return array{subject: Model&Authenticatable, evidence: AuthenticationEvidence} */
    public function consume(#[\SensitiveParameter] string $proof, AuthenticationDestination $destination, AuthenticationRequestContext $context): array
    {
        $consumed = $this->consumeForFinalization($proof, $destination, $context);

        return ['subject' => $consumed['subject'], 'evidence' => $consumed['evidence']];
    }

    /**
     * Retain the private verified snapshot only for native finalizer rechecks.
     *
     * @internal
     *
     * @return array{subject: Model&Authenticatable, evidence: AuthenticationEvidence, verification: AuthenticationVerification}
     */
    public function consumeForFinalization(#[\SensitiveParameter] string $proof, AuthenticationDestination $destination, AuthenticationRequestContext $context): array
    {
        $snapshot = $this->find($proof);
        $candidate = $this->subject($snapshot);

        $verification = null;
        try {
            return $candidate->getConnection()->transaction(function () use ($proof, $destination, $context, $candidate, &$verification): array {
                $this->security->lock($candidate);
                $this->security->lockChallenges($candidate);
                $challenge = $this->find($proof, true);
                $verification = $this->verification($challenge, $destination, $context);
                $subject = $this->recheck($verification);
                $challenge->consumed_at = CarbonImmutable::now('UTC');
                $this->records->save($challenge);

                return ['subject' => $subject, 'evidence' => $verification->evidence, 'verification' => $verification];
            });
        } catch (AuthException $exception) {
            if ($exception->errorCode === 'second_factor_required' && $destination === AuthenticationDestination::Session
                && $verification?->evidence->method === AuthenticationMethod::Password) {
                $this->audits->record('authentication.factor_required', subject: $verification->evidence->subject, actor: $candidate);
            }
            throw $exception;
        }
    }

    /** Complete a primary capability using a native one-use factor; no method/factor claims accepted.
     * @param  array{code?: mixed, recoveryCode?: mixed}  $factorProof
     */
    public function completeFactor(#[\SensitiveParameter] string $proof, AuthenticationDestination $destination, AuthenticationRequestContext $context, #[\SensitiveParameter] array $factorProof): IssuedAuthenticationProof
    {
        if (array_diff(array_keys($factorProof), ['code', 'recoveryCode']) !== [] || count($factorProof) !== 1) {
            throw new \InvalidArgumentException('Exactly one native factor proof is required.');
        }
        $value = current($factorProof);
        if (! is_string($value) || trim($value) === '' || strlen($value) > 128) {
            throw new \InvalidArgumentException('Factor proof must be a bounded non-empty string.');
        }
        $candidate = $this->subject($this->find($proof));
        $result = $candidate->getConnection()->transaction(function () use ($proof, $destination, $context, $factorProof, $candidate): IssuedAuthenticationProof|Throwable {
            $this->security->lock($candidate);
            $this->security->lockChallenges($candidate);
            $challenge = $this->find($proof, true);
            $verification = $this->verification($challenge, $destination, $context);
            $evidence = $verification->evidence;
            $subject = $this->recheck($verification, assurance: false);
            $challenge->attempts++;
            $this->records->save($challenge);
            try {
                if (isset($factorProof['code'])) {
                    $this->secondFactor->verify($subject, ['code' => $factorProof['code']]);
                    $factor = 'totp';
                } else {
                    $this->secondFactor->consumeRecoveryCode($subject, ['code' => $factorProof['recoveryCode'] ?? null]);
                    $factor = 'recovery';
                }
                $payload = $challenge->payload;
                $payload['factors'] = array_values(array_unique([...$evidence->factors, $factor]));
                $challenge->payload = $payload;
                $challenge->attempts = 0;
                $this->records->save($challenge);

                return new IssuedAuthenticationProof($proof);
            } catch (Throwable $exception) {
                return $exception;
            }
        });
        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }

    /** Recheck authoritative source, password, revision, eligibility and assurance around consumer hooks.
     * This method grants no authentication authority without consumption by a native finalizer.
     *
     * @internal
     */
    public function recheck(#[\SensitiveParameter] AuthenticationVerification $verification, bool $assurance = true): Model&Authenticatable
    {
        $evidence = $verification->evidence;
        $subject = $this->canonical($verification);
        $this->nativeEligibility->assertEligible($subject, $evidence->method->purpose());
        $this->eligibility->assertEligible($subject, $evidence->method->purpose());
        if ($assurance) {
            $this->enrollment->assertSatisfied($subject, $evidence, $evidence->method->purpose());
            $this->assurance->assertSatisfied($subject, $evidence, $evidence->method->purpose());
        }
        $subject = $this->canonical($verification);
        $this->nativeEligibility->assertEligible($subject, $evidence->method->purpose());
        if ($assurance) {
            $this->enrollment->assertSatisfied($subject, $evidence, $evidence->method->purpose());
        }

        return $subject;
    }

    private function canonical(#[\SensitiveParameter] AuthenticationVerification $verification): Model&Authenticatable
    {
        $evidence = $verification->evidence;
        $candidate = $this->subjects->resolve($evidence->subject);
        if (! $candidate instanceof Model) {
            throw $this->invalid();
        }
        try {
            $subject = $this->actors->resolve($candidate, lock: true);
        } catch (AuthorizationException $exception) {
            throw new AuthException('subject_unavailable', 'The authenticated subject is unavailable.', 404, previous: $exception);
        }
        if (! $subject instanceof Model || SubjectReference::fromAuthenticatable($subject) != $evidence->subject
            || $subject->getConnection() !== (new Challenge)->getConnection()
            || $this->security->lock($subject)->revision !== $evidence->revision
            || $evidence->method === AuthenticationMethod::Password && ! $verification->matchesPasswordBinding($this->hasher->hash('native-password-proof', $subject->getAuthPassword()))) {
            throw $this->invalid();
        }

        if ($evidence->method === AuthenticationMethod::Remember) {
            $remember = RememberCredential::query()->whereKey($evidence->provider)->where('subject_type', $evidence->subject->type)->where('subject_id', $evidence->subject->identifier)->where('guard_name', $evidence->context->guardName)->first();
            if ($remember === null || $remember->consumed_at === null || $remember->revoked_at !== null || $remember->rotated_to_id !== null || ! $remember->absolute_expires_at->isFuture() || $remember->security_revision !== $evidence->revision || $evidence->context->guardName === null || $remember->provider_hash !== AuthBrowserSessions::providerFingerprint($evidence->context->guardName)) {
                throw $this->invalid();
            }
        }

        return $subject;
    }

    /** Non-consuming continuation availability; never establishes a principal. */
    public function available(#[\SensitiveParameter] string $proof): bool
    {
        try {
            $challenge = $this->find($proof);
            $subject = $this->subject($challenge);
            $subject->getConnection()->transaction(fn () => $this->recheck(AuthenticationVerification::fromChallenge($challenge), assurance: false));

            return true;
        } catch (AuthException) {
            return false;
        }
    }

    private function find(#[\SensitiveParameter] string $proof, bool $lock = false): Challenge
    {
        if (preg_match('/\A[0-9a-f]{64}\z/', $proof) !== 1) {
            throw $this->invalid();
        }
        $query = $this->records->query()->where('type', 'authentication_proof')->where('secret_hash', $this->hasher->hash('native-authentication-proof', $proof));
        $challenge = ($lock ? $query->lockForUpdate() : $query)->first();
        if (! $challenge instanceof Challenge || ! $challenge->isUsable()) {
            throw $this->invalid();
        }

        return $challenge;
    }

    private function verification(#[\SensitiveParameter] Challenge $challenge, AuthenticationDestination $destination, AuthenticationRequestContext $context): AuthenticationVerification
    {
        $context->assertBound($destination);
        $verification = AuthenticationVerification::fromChallenge($challenge);
        $evidence = $verification->evidence;
        if ($evidence->destination !== $destination || $evidence->context->facts() !== $context->facts()) {
            throw $this->invalid();
        }

        return $verification;
    }

    private function subject(Challenge $challenge): Model&Authenticatable
    {
        if (! is_string($challenge->subject_type) || ! is_string($challenge->subject_id)) {
            throw $this->invalid();
        }
        $reference = new SubjectReference($challenge->subject_type, $challenge->subject_id);
        $subject = $this->subjects->resolve($reference);
        if (! $subject instanceof Model || SubjectReference::fromAuthenticatable($subject) != $reference || $subject->getConnection() !== $challenge->getConnection()) {
            throw $this->invalid();
        }

        return $subject;
    }

    private function invalid(): AuthException
    {
        return new AuthException('authentication_proof_invalid', 'The authentication proof is invalid or expired.', 422);
    }
}

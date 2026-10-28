<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthenticationMethod;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthenticationVerification;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use SensitiveParameter;

/**
 * Native mandatory authorization, independent of optional consumer policy.
 *
 * @internal
 */
final readonly class RecentAuthenticationProofs
{
    public function __construct(private PrincipalSecurity $security, private AuthIdentityChallenges $records, private SecretHasher $hasher, private CanonicalActorResolver $canonical, private PrincipalEligibility $eligibility, private AccountConfirmation $policy, private AuthConfiguration $configuration) {}

    public function consume(Authenticatable $subject, #[SensitiveParameter] ?string $grant, RecentAuthenticationPurpose $purpose, ?AuthenticationRequestContext $context): void
    {
        if (! $subject instanceof Model || $subject->getConnection()->transactionLevel() === 0) {
            throw new \LogicException('Recent grants must be consumed inside the sensitive mutation transaction.');
        }
        [$principal, $challenge, $verification] = $this->validate($subject, $grant, $purpose, $context, true);
        $this->policy->assertConfirmed($principal, $verification->evidence, $purpose);
        $this->validate($principal, $grant, $purpose, $context, true);
        $challenge->consumed_at = CarbonImmutable::now();
        $this->records->save($challenge);
    }

    /** Read-only preflight before external ceremony work; final consumption rechecks under lock. */
    public function assertValid(Authenticatable $subject, #[SensitiveParameter] ?string $grant, RecentAuthenticationPurpose $purpose, ?AuthenticationRequestContext $context): void
    {
        $this->validate($subject, $grant, $purpose, $context, false);
    }

    /** @return array{Model&Authenticatable, Challenge, AuthenticationVerification} */
    private function validate(Authenticatable $subject, #[SensitiveParameter] ?string $grant, RecentAuthenticationPurpose $purpose, ?AuthenticationRequestContext $context, bool $lock): array
    {
        if ($context === null || $grant === null || preg_match('/\A[0-9a-f]{64}\z/', $grant) !== 1) {
            throw $this->invalid();
        }
        $context->assertBound(AuthenticationDestination::Reauthentication);
        $principal = $this->canonical->resolve($subject, $lock);
        if (! $principal instanceof Model || $principal->getConnection() !== (new Challenge)->getConnection()) {
            throw $this->invalid();
        }
        $reference = SubjectReference::fromAuthenticatable($principal);
        $revision = $lock ? $this->security->lock($principal)->revision : $this->security->revisionSnapshot($principal);
        if ($lock) {
            $this->security->lockChallenges($principal);
        }
        $query = $this->records->query()->where('type', 'recent_authentication')->where('secret_hash', $this->hasher->hash('native-recent-authentication', $grant));
        $challenge = ($lock ? $query->lockForUpdate() : $query)->first();
        if (! $challenge instanceof Challenge || ! $challenge->isUsable() || $challenge->purpose !== $purpose->value
            || $challenge->subject_type !== $reference->type || $challenge->subject_id !== $reference->identifier) {
            throw $this->invalid();
        }
        $method = $challenge->payload['method'] ?? null;
        $method = is_string($method) ? AuthenticationMethod::tryFrom($method) : null;
        if ($method === null) {
            throw $this->invalid();
        }
        $snapshot = clone $challenge;
        $snapshot->type = 'authentication_proof';
        $snapshot->purpose = $method->purpose()->value;
        $verification = AuthenticationVerification::fromChallenge($snapshot);
        $evidence = $verification->evidence;
        if ($evidence->destination !== AuthenticationDestination::Reauthentication || $evidence->revision !== $revision
            || $evidence->context->guardName !== $context->guardName || $evidence->context->sessionBinding !== $context->sessionBinding
            || $method === AuthenticationMethod::Password && ! $verification->matchesPasswordBinding($this->hasher->hash('native-password-proof', $principal->getAuthPassword()))) {
            throw $this->invalid();
        }
        if ($this->configuration->featureEnabled(AuthFeature::ManagedSessions)) {
            if ($context->browserSessionId === null || $context->browserBinding === null || $evidence->context->browserSessionId !== $context->browserSessionId || $evidence->context->browserBinding !== $context->browserBinding) {
                throw $this->invalid();
            }
            $query = BrowserSession::query()->whereKey($context->browserSessionId)->where('binding_hash', $this->hasher->hash('native-browser-binding', $context->browserBinding))->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $context->guardName);
            $browser = ($lock ? $query->lockForUpdate() : $query)->first();
            if ($browser === null || ! $browser->isCurrent($revision) || $context->guardName === null || $browser->provider_hash !== AuthBrowserSessions::providerFingerprint($context->guardName)) {
                throw $this->invalid();
            }
        }
        $this->eligibility->assertEligible($principal, $method->purpose());

        return [$principal, $challenge, $verification];
    }

    private function invalid(): AuthException
    {
        return new AuthException('recent_authentication_required', 'A current operation-bound authentication grant is required.', 422);
    }
}

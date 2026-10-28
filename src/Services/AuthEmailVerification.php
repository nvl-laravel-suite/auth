<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\User;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use Nvl\Support\Events\ConnectionCommitCallbacks;
use Nvl\Support\Events\DomainEventDispatcher;

/** Complete native initial email verification using one-use current-destination proofs.
 *
 * @api
 */
final readonly class AuthEmailVerification
{
    public function __construct(private FeatureGate $features, private AuthDeliveryContext $deliveryContext, private AuthConfiguration $configuration, private AuthAuditRecorder $audits, private DomainEventDispatcher $domainEvents, private ConnectionCommitCallbacks $eventCommits, private PrincipalSecurity $security, private CanonicalActorResolver $canonical, private AuthIdentityChallenges $records, private SecretHasher $hasher) {}

    /** Issue verification through typed delivery after the owning outer commit. */
    public function request(Authenticatable&MustVerifyEmail $subject, ?string $locale = null): void
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);
        $subject = $this->principal($subject);
        $delivery = $this->deliveryContext->capture(true);
        $subject->getConnection()->transaction(function () use ($subject, $locale, $delivery): void {
            $revision = $this->security->lock($subject)->revision;
            $this->security->lockChallenges($subject);
            $subject = $this->principal($this->canonical->resolve($subject, true));
            if ($subject->hasVerifiedEmail()) {
                return;
            }
            $reference = SubjectReference::fromAuthenticatable($subject);
            $secret = bin2hex(random_bytes(32));
            $expiresAt = CarbonImmutable::now('UTC')->addMinutes($this->configuration->integerBetween('features.email_verification.settings.ttl_minutes', 60, 1, 10080));
            $challenge = $this->records->create(['type' => 'native_email_verification', 'purpose' => 'initial_email_verification', 'subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'secret_hash' => $this->hasher->hash('native-email-verification', $secret), 'payload' => ['email' => $subject->getEmailForVerification(), 'key' => PrincipalEmailIdentity::key($subject->getEmailForVerification()), 'revision' => $revision], 'expires_at' => $expiresAt, 'max_attempts' => 5, 'attempts' => 0]);
            $token = $challenge->id.'.'.$secret;
            $this->domainEvents->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::EmailVerification, type: AuthMessageType::EmailVerification, recipient: trim($subject->getEmailForVerification()), payload: ['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'token' => $token], expiresAt: $expiresAt, locale: $locale), $delivery), $subject->getConnection());
            $this->audits->record('email_verification.requested', subject: $reference, actor: $subject);
        });
    }

    /** Consume a proof before changing verification; invalid proofs never become idempotent success. */
    public function verify(Authenticatable&MustVerifyEmail $subject, #[\SensitiveParameter] string $token): bool
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Use);
        $subject = $this->principal($subject);
        $result = $subject->getConnection()->transaction(function () use ($subject, $token): ?bool {
            $revision = $this->security->lock($subject)->revision;
            $this->security->lockChallenges($subject);
            $fresh = $this->principal($this->canonical->resolve($subject, true));
            $reference = SubjectReference::fromAuthenticatable($fresh);
            $parts = strlen($token) === 101 ? explode('.', $token, 2) : [];
            $challenge = count($parts) === 2 && Str::isUuid($parts[0]) && preg_match('/^[a-f0-9]{64}$/D', $parts[1]) === 1
                ? $this->records->query()->whereKey($parts[0])->where('type', 'native_email_verification')->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->lockForUpdate()->first()
                : null;
            if ($challenge === null || ! $challenge->isUsable()) {
                return null;
            }
            $payload = $challenge->payload ?? [];
            if (! hash_equals($challenge->secret_hash, $this->hasher->hash('native-email-verification', $parts[1]))
                || ($payload['revision'] ?? null) !== $revision
                || ($payload['email'] ?? null) !== $fresh->getEmailForVerification()
                || $subject->getEmailForVerification() !== $fresh->getEmailForVerification()
                || ($payload['key'] ?? null) !== $fresh->getAttribute($fresh->getEmailIdentityHashName())) {
                $challenge->attempts++;
                $this->records->save($challenge);
                $this->audits->record('email_verification.failed', outcome: 'failure', subject: $reference, actor: $fresh);

                return null;
            }
            $challenge->consumed_at = CarbonImmutable::now('UTC');
            $this->records->save($challenge);
            if ($fresh->hasVerifiedEmail()) {
                return false;
            }
            if (! $fresh->markEmailAsVerified()) {
                throw new AuthException('verification_failed', 'The email verification state could not be saved.', 500);
            }
            $event = new Verified($fresh);
            $this->eventCommits->afterCommit($fresh->getConnection(), static function () use ($event): void {
                event($event);
            });
            $this->audits->record('email.verified', subject: $reference, actor: $fresh);

            return true;
        });
        if ($result === null) {
            throw new AuthException('verification_invalid', 'The email verification proof is invalid.', 403);
        }

        return $result;
    }

    private function principal(Authenticatable $subject): User
    {
        if (! $subject instanceof User || ! $subject->exists || $subject->getConnection() !== (new Challenge)->getConnection() || $subject->getConnection() !== (new AuthAudit)->getConnection()) {
            throw AuthException::invalidConfiguration('Native verification requires a persisted canonical principal and proof/audit storage on one source.');
        }
        PrincipalEmailIdentity::assertReady($subject);

        return $subject;
    }
}

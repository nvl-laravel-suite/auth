<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\PrincipalAttributeMapper;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\AuthMessageType;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\AccountSecurityChanged;
use Nvl\Auth\Events\AuthDeliveryRequested;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Challenge;
use Nvl\Auth\Models\PendingEmailChange;
use Nvl\Auth\Models\User;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\ValueObjects\AuthDeliveryRequest;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;
use Nvl\Support\Events\DomainEventDispatcher;

/** Keeps live identity unchanged until the replacement mailbox is proved. @api */
final readonly class AuthEmailChanges
{
    public function __construct(private FeatureGate $features, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private RecentAuthenticationProofs $recent, private SecretHasher $hasher, private PrincipalAttributeMapper $attributes, private AuthPipeline $pipeline, private AuthAuditRecorder $audits, private DomainEventDispatcher $events, private AuthDeliveryContext $delivery) {}

    public function request(Authenticatable $subject, string $newEmail, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): PendingEmailChange
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Issue);
        $newEmail = PrincipalEmailIdentity::normalize($newEmail);
        Validator::make(['email' => $newEmail], ['email' => ['required', 'email:rfc', 'max:254']])->validate();
        $user = $this->principal($subject);
        $context->assertBound(AuthenticationDestination::Reauthentication);

        return $user->getConnection()->transaction(function () use ($user, $newEmail, $recentProof, $context): PendingEmailChange {
            return $this->pipeline->run('email_change', new AuthPipelineContext('email_change', ['operation' => 'request'], SubjectReference::fromAuthenticatable($user)), function () use ($user, $newEmail, $recentProof, $context): PendingEmailChange {
                $this->recent->consume($user, $recentProof, RecentAuthenticationPurpose::EmailChange, $context);
                $revision = $this->security->lock($user)->revision;
                $this->security->lockChallenges($user);
                $fresh = $this->principal($user);
                $reference = SubjectReference::fromAuthenticatable($fresh);
                if (PrincipalEmailIdentity::normalize($fresh->getEmailForVerification()) === $newEmail) {
                    throw new AuthException('email_change_unavailable', 'The email change is unavailable.', 422);
                }
                PendingEmailChange::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNotNull('active_key')->update(['revoked_at' => now(), 'active_key' => null]);
                $secret = bin2hex(random_bytes(32));
                $expiry = CarbonImmutable::now('UTC')->addMinutes(60);
                $pending = PendingEmailChange::query()->create(['subject_type' => $reference->type, 'subject_id' => $reference->identifier, 'new_email' => $newEmail, 'email_hash' => $this->hasher->hash('pending-email-identity', $newEmail), 'token_hash' => $this->hasher->hash('pending-email-proof', $secret), 'security_revision' => $revision, 'active_key' => $this->hasher->hash('pending-email-active', $reference->type."\0".$reference->identifier), 'context' => ['guard' => $context->guardName, 'binding' => $this->hasher->hash('pending-email-browser', (string) $context->sessionBinding)], 'expires_at' => $expiry]);
                $this->notify($newEmail, AuthMessageType::EmailChangeVerification, ['token' => $pending->identifier().'.'.$secret], $expiry, $fresh);
                $this->notify($fresh->getEmailForVerification(), AuthMessageType::EmailChangeNotification, ['change_id' => $pending->identifier(), 'stage' => 'requested'], $expiry, $fresh);
                $this->audits->record('email_change.requested', subject: $reference, actor: $fresh, metadata: ['change_id' => $pending->identifier()]);

                return $pending;
            });
        }, 3);
    }

    public function complete(Authenticatable $subject, #[\SensitiveParameter] string $token, AuthenticationRequestContext $context): User
    {
        $this->features->assertAllowed(AuthFeature::EmailVerification, FeatureOperation::Use);
        $user = $this->principal($subject);
        $context->assertBound(AuthenticationDestination::Reauthentication);
        try {
            return $user->getConnection()->transaction(function () use ($user, $token, $context): User {
                return $this->pipeline->run('email_change', new AuthPipelineContext('email_change', ['operation' => 'complete'], SubjectReference::fromAuthenticatable($user)), function () use ($user, $token, $context): User {
                    $revision = $this->security->lock($user)->revision;
                    $this->security->lockChallenges($user);
                    $fresh = $this->principal($user);
                    $reference = SubjectReference::fromAuthenticatable($fresh);
                    $parts = strlen($token) === 101 ? explode('.', $token, 2) : [];
                    $pending = count($parts) === 2 && Str::isUuid($parts[0]) && preg_match('/\A[0-9a-f]{64}\z/', $parts[1]) === 1 ? PendingEmailChange::query()->whereKey($parts[0])->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->lockForUpdate()->first() : null;
                    if ($pending === null || $pending->revoked_at !== null || $pending->consumed_at !== null || $pending->active_key === null || ! $pending->expires_at->isFuture() || $pending->security_revision !== $revision || $pending->context !== ['guard' => $context->guardName, 'binding' => $this->hasher->hash('pending-email-browser', (string) $context->sessionBinding)] || ! hash_equals($pending->token_hash, $this->hasher->hash('pending-email-proof', $parts[1]))) {
                        throw $this->invalid();
                    }
                    $oldEmail = $fresh->getEmailForVerification();
                    $fresh->update($this->attributes->map(['email' => $pending->new_email, 'emailVerified' => true]));
                    $pending->consumed_at = CarbonImmutable::now('UTC');
                    $pending->active_key = null;
                    $pending->save();
                    $this->security->advance($fresh, 'email_changed');
                    $this->audits->record('email_change.completed', subject: $reference, actor: $fresh, metadata: ['change_id' => $pending->identifier()]);
                    $expiry = CarbonImmutable::now('UTC')->addHour();
                    foreach ([$oldEmail, $fresh->getEmailForVerification()] as $email) {
                        $this->notify($email, AuthMessageType::EmailChangeNotification, ['change_id' => $pending->identifier(), 'stage' => 'completed'], $expiry, $fresh);
                    }
                    $this->events->dispatch(new AccountSecurityChanged($reference, 'email_changed'), $fresh->getConnection());

                    return $fresh->refresh();
                });
            }, 3);
        } catch (UniqueConstraintViolationException) {
            throw $this->invalid();
        }
    }

    public function cancel(Authenticatable $subject, string $changeId): void
    {
        $user = $this->principal($subject);
        $user->getConnection()->transaction(function () use ($user, $changeId): void {
            $this->security->lock($user);
            $reference = SubjectReference::fromAuthenticatable($user);
            $pending = PendingEmailChange::query()->whereKey($changeId)->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->lockForUpdate()->first();
            if ($pending !== null && $pending->active_key !== null) {
                $pending->revoked_at = CarbonImmutable::now('UTC');
                $pending->active_key = null;
                $pending->save();
            }
        });
    }

    private function principal(Authenticatable $subject): User
    {
        $user = $this->canonical->resolve($subject);
        if (! $user instanceof User || $user->getConnection() !== (new PendingEmailChange)->getConnection() || $user->getConnection() !== (new Challenge)->getConnection() || $user->getConnection() !== (new AuthAudit)->getConnection()) {
            throw AuthException::invalidConfiguration('Email changes require one canonical source.');
        }
        PrincipalEmailIdentity::assertReady($user);

        return $user;
    }

    /** @param array<string, mixed> $payload */
    private function notify(string $email, AuthMessageType $type, #[\SensitiveParameter] array $payload, CarbonImmutable $expiry, User $user): void
    {
        $this->events->dispatch(new AuthDeliveryRequested(new AuthDeliveryRequest(messageId: (string) Str::uuid(), feature: AuthFeature::EmailVerification, type: $type, recipient: $email, payload: $payload, expiresAt: $expiry, subject: SubjectReference::fromAuthenticatable($user)), $this->delivery->capture(true)), $user->getConnection());
    }

    private function invalid(): AuthException
    {
        return new AuthException('email_change_unavailable', 'The email change is unavailable or expired.', 422);
    }
}

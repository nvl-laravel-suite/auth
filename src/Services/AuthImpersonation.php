<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\AuthSubjectResolver;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\ImpersonationChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Pipelines\AuthPipeline;
use Nvl\Auth\Support\SubjectReferences;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\AuthPipelineContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Auth\ValueObjects\SystemMutationContext;
use Nvl\Support\Auth\CanonicalActorResolver;
use Nvl\Support\Events\DomainEventDispatcher;
use Nvl\Support\Ownership\Contracts\OwnershipContext;

/**
 * Complete durable grant lifecycle; request overlays separately re-admit this authority.
 *
 * @api
 */
final readonly class AuthImpersonation
{
    public function __construct(private FeatureGate $features, private AuthenticationSessions $transitions, private AuthBrowserSessions $sessions, private RecentAuthenticationProofs $recent, private PrincipalSecurity $security, private CanonicalActorResolver $canonical, private AuthSubjectResolver $subjects, private PrincipalEligibility $eligibility, private ImpersonationAccess $access, private OwnershipContext $ownership, private AuthOwnerAdmission $owners, private AuthAuditRecorder $audits, private AuthPipeline $pipeline, private SecretHasher $hasher, private MutationAuthorizer $management, private AuthOperationBoundary $operations, private AuthConfiguration $configuration, private DomainEventDispatcher $events) {}

    /** @param array<string, mixed> $data */
    public function start(Authenticatable $actor, Authenticatable $target, #[\SensitiveParameter] string $recentProof, array $data, AuthenticationRequestContext $context): Impersonation
    {
        $this->features->assertAllowed(AuthFeature::Impersonation, FeatureOperation::Issue);
        $this->transitions->assertCanTransition();
        $duration = array_key_exists('durationSeconds', $data) ? $data['durationSeconds'] : $this->configuration->integerBetween('features.impersonation.settings.duration_seconds', 900, 60, 1800);
        if (array_diff(array_keys($data), ['reason', 'durationSeconds']) !== [] || ! is_string($data['reason'] ?? null) || trim($data['reason']) === '' || mb_strlen($data['reason']) > 500 || ! is_int($duration) || $duration < 60 || $duration > 1800) {
            throw new \InvalidArgumentException('Impersonation requires a bounded reason and a 60–1800 second duration.');
        }
        $data = ['reason' => trim($data['reason']), 'durationSeconds' => $duration];
        [$actor, $target] = $this->principals($actor, $target);
        $owner = $this->ownership->snapshot()->owner;
        $this->assertAccess($actor, $target);

        return $actor->getConnection()->transaction(function () use ($actor, $target, $recentProof, $data, $context, $owner): Impersonation {
            [$actorRevision, $targetRevision] = $this->lock($actor, $target);
            $browser = $this->browser($actor, $context);
            $existing = Impersonation::query()->where('browser_session_id', $browser->identifier())->whereNotNull('active_session_key')->lockForUpdate()->first();
            if ($existing !== null && $existing->expires_at->isFuture()) {
                throw new AuthException('impersonation_active', 'This browser already has an active impersonation.', 409);
            }
            if ($existing !== null) {
                $existing->update(['stopped_at' => now(), 'stop_reason' => 'expired', 'active_session_key' => null]);
                $this->audits->record('impersonation.expired', subject: new SubjectReference($existing->effective_subject_type, $existing->effective_subject_id), actor: $actor, metadata: ['grant_id' => $existing->identifier()]);
                $this->fact($existing, 'expired', $actor);
            }
            $created = $this->pipeline->run('impersonation_started', new AuthPipelineContext('impersonation_started', ['durationSeconds' => $data['durationSeconds']], SubjectReference::fromAuthenticatable($actor)), function () use ($actor, $target, $recentProof, $data, $context, $owner, $actorRevision, $targetRevision, $browser): Impersonation {
                $this->assertAccess($actor, $target);
                $this->recent->consume($actor, $recentProof, RecentAuthenticationPurpose::ImpersonationStart, $context);
                $this->assertAccess($actor, $target);
                $a = SubjectReference::fromAuthenticatable($actor);
                $t = SubjectReference::fromAuthenticatable($target);
                $now = CarbonImmutable::now('UTC');
                $grant = Impersonation::query()->create(['actor_type' => $a->type, 'actor_id' => $a->identifier, 'effective_subject_type' => $t->type, 'effective_subject_id' => $t->identifier, 'browser_session_id' => $browser->identifier(), 'guard_name' => $context->guardName, 'actor_revision' => $actorRevision, 'target_revision' => $targetRevision, 'reason' => trim($data['reason']), 'owner_reference' => $owner?->toArray(), 'active_session_key' => $this->hasher->hash('native-impersonation-active', $browser->identifier()), 'started_at' => $now, 'expires_at' => $now->addSeconds($data['durationSeconds'])]);
                $this->audits->record('impersonation.granted', subject: $t, actor: $actor, metadata: ['grant_id' => $grant->identifier(), 'owner' => $grant->owner_reference, 'browser_session_id' => $browser->identifier()]);
                $this->fact($grant, 'granted', $actor);

                return $grant;
            });
            $this->assertAccess($actor, $target);
            $this->browser($actor, $context);
            $fresh = Impersonation::query()->whereKey($created->identifier())->lockForUpdate()->firstOrFail();
            $a = SubjectReference::fromAuthenticatable($actor);
            $t = SubjectReference::fromAuthenticatable($target);
            if ($fresh->actor_type !== $a->type || $fresh->actor_id !== $a->identifier || $fresh->effective_subject_type !== $t->type || $fresh->effective_subject_id !== $t->identifier || $fresh->browser_session_id !== $browser->identifier() || $this->lock($actor, $target) !== [$actorRevision, $targetRevision]) {
                throw $this->invalid();
            }

            return $fresh;
        }, 3);
    }

    /** @return array{grant: Impersonation, actor: Model&Authenticatable, target: Model&Authenticatable} */
    public function admit(Authenticatable $actor, string $impersonationId, AuthenticationRequestContext $context): array
    {
        $this->features->assertAllowed(AuthFeature::Impersonation, FeatureOperation::Use);
        $reference = SubjectReference::fromAuthenticatable($actor);
        $snapshot = Impersonation::query()->whereKey($impersonationId)->where('actor_type', $reference->type)->where('actor_id', $reference->identifier)->first();
        $target = $snapshot === null ? null : $this->subjects->resolve(new SubjectReference($snapshot->effective_subject_type, $snapshot->effective_subject_id));
        if ($snapshot === null || $target === null) {
            throw $this->invalid();
        }
        [$actor, $target] = $this->principals($actor, $target);
        $result = $actor->getConnection()->transaction(function () use ($actor, $target, $snapshot, $context): ?array {
            [$actorRevision, $targetRevision] = $this->lock($actor, $target);
            $browser = $this->browser($actor, $context);
            $grant = Impersonation::query()->whereKey($snapshot->identifier())->lockForUpdate()->first();
            $a = SubjectReference::fromAuthenticatable($actor);
            $t = SubjectReference::fromAuthenticatable($target);
            if ($grant === null || $grant->actor_type !== $a->type || $grant->actor_id !== $a->identifier || $grant->effective_subject_type !== $t->type || $grant->effective_subject_id !== $t->identifier || $grant->stopped_at !== null || $grant->active_session_key === null || $grant->browser_session_id !== $browser->identifier() || $grant->guard_name !== $context->guardName || $grant->actor_revision !== $actorRevision || $grant->target_revision !== $targetRevision || $grant->owner_reference !== $this->ownership->snapshot()->owner?->toArray()) {
                throw $this->invalid();
            }
            if (! $grant->expires_at->isFuture()) {
                $grant->update(['stopped_at' => now(), 'stop_reason' => 'expired', 'active_session_key' => null]);
                $this->audits->record('impersonation.expired', subject: $t, actor: $actor, metadata: ['grant_id' => $grant->identifier()]);
                $this->fact($grant, 'expired', $actor);

                return null;
            }
            $this->assertAccess($actor, $target);

            return ['grant' => $grant, 'actor' => $actor, 'target' => $target];
        }, 3);

        return $result ?? throw $this->invalid();
    }

    public function stop(Authenticatable $actor, string $impersonationId, AuthenticationRequestContext $context, string $reason = 'requested'): Impersonation
    {
        if (! in_array($reason, ['requested', 'admission_denied', 'transition_failed'], true)) {
            throw new \InvalidArgumentException('Invalid impersonation stop reason.');
        }
        $this->features->assertAllowed(AuthFeature::Impersonation, FeatureOperation::Revoke);
        $this->transitions->assertCanTransition();
        $reference = SubjectReference::fromAuthenticatable($actor);
        $browser = BrowserSession::query()->whereKey($context->browserSessionId)->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $context->guardName)->where('binding_hash', $this->hasher->hash('native-browser-binding', $context->browserBinding ?? ''))->first();
        if ($browser === null) {
            throw $this->invalid();
        }

        return $browser->getConnection()->transaction(function () use ($actor, $impersonationId, $browser, $reference, $reason): Impersonation {
            $grant = Impersonation::query()->whereKey($impersonationId)->where('actor_type', $reference->type)->where('actor_id', $reference->identifier)->where('browser_session_id', $browser->identifier())->lockForUpdate()->first();
            if ($grant === null) {
                throw $this->invalid();
            }

            return $this->pipeline->run('impersonation_stopped', new AuthPipelineContext('impersonation_stopped', subject: $reference), function () use ($grant, $actor, $reason): Impersonation {
                if ($grant->stopped_at === null) {
                    $grant->update(['stopped_at' => now(), 'stop_reason' => $reason, 'active_session_key' => null]);
                    $this->audits->record('impersonation.stopped', subject: new SubjectReference($grant->effective_subject_type, $grant->effective_subject_id), actor: $actor, metadata: ['grant_id' => $grant->identifier(), 'owner' => $grant->owner_reference, 'reason' => $reason]);
                    $this->fact($grant, 'stopped', $actor);
                }

                return $grant;
            });
        }, 3);
    }

    public function revoke(Authenticatable|SystemMutationContext $authority, string $impersonationId, string $reason): Impersonation
    {
        if (trim($reason) === '' || mb_strlen($reason) > 500) {
            throw new \InvalidArgumentException('A bounded revocation reason is required.');
        }
        $this->operations->requirePlatformAdministration();
        $grant = Impersonation::query()->find($impersonationId) ?? throw $this->invalid();
        $actor = $this->management->authorize($authority, 'nvl.auth.impersonations.revoke', $grant);

        return $grant->getConnection()->transaction(function () use ($grant, $authority, $reason): Impersonation {
            $grant = Impersonation::query()->whereKey($grant->identifier())->lockForUpdate()->firstOrFail();
            $actor = $this->management->authorize($authority, 'nvl.auth.impersonations.revoke', $grant);
            if ($grant->stopped_at === null) {
                $grant->update(['stopped_at' => now(), 'stop_reason' => 'administrative', 'active_session_key' => null]);
                $this->audits->record('impersonation.revoked', subject: new SubjectReference($grant->effective_subject_type, $grant->effective_subject_id), actor: $actor, metadata: ['grant_id' => $grant->identifier(), 'impersonator_type' => $grant->actor_type, 'impersonator_id' => $grant->actor_id, 'owner' => $grant->owner_reference, 'reason' => $reason, ...$this->management->metadata($authority)]);
                $this->fact($grant, 'revoked', $actor);
            }

            return $grant;
        });
    }

    /** @return array{Model&Authenticatable, Model&Authenticatable} */
    private function principals(Authenticatable $actor, Authenticatable $target): array
    {
        $actor = $this->canonical->resolve($actor);
        $target = $this->canonical->resolve($target);
        if (! $actor instanceof Model || ! $target instanceof Model || $actor->getConnection() !== $target->getConnection() || $actor->getConnection() !== (new Impersonation)->getConnection() || $actor->getConnection() !== (new AuthAudit)->getConnection() || SubjectReferences::same(SubjectReference::fromAuthenticatable($actor), SubjectReference::fromAuthenticatable($target))) {
            throw $this->invalid();
        }

        return [$actor, $target];
    }

    /**
     * @return array{int, int}
     */
    private function lock(Model&Authenticatable $actor, Model&Authenticatable $target): array
    {
        $ordered = [$actor, $target];
        usort($ordered, static function (Model&Authenticatable $a, Model&Authenticatable $b): int {
            $first = SubjectReference::fromAuthenticatable($a);
            $second = SubjectReference::fromAuthenticatable($b);

            return strcmp($first->type.':'.$first->identifier, $second->type.':'.$second->identifier);
        });
        foreach ($ordered as $principal) {
            $this->security->lock($principal);
        }

        return [$this->security->lock($actor)->revision, $this->security->lock($target)->revision];
    }

    private function browser(Authenticatable $actor, AuthenticationRequestContext $context): BrowserSession
    {
        $browser = $this->sessions->admit($actor, $context->guardName ?? '', $context->browserBinding ?? '');
        if ($browser->identifier() !== $context->browserSessionId) {
            throw $this->invalid();
        }

        return $browser;
    }

    private function assertAccess(Authenticatable $actor, Authenticatable $target): void
    {
        $snapshot = $this->ownership->snapshot();
        if ($snapshot->publicSite !== null) {
            throw $this->invalid();
        }
        $this->eligibility->assertEligible($this->canonical->resolve($actor), AuthenticationPurpose::CredentialLogin);
        $this->eligibility->assertEligible($this->canonical->resolve($target), AuthenticationPurpose::CredentialLogin);
        if ($snapshot->owner !== null) {
            $this->owners->assertAllowed($actor);
            $this->owners->assertAllowed($target);
        }
        $this->access->assertAllowed($actor, $target, $snapshot->owner);
    }

    private function fact(Impersonation $grant, string $operation, ?Authenticatable $operator): void
    {
        $this->events->dispatch(new ImpersonationChanged($grant->identifier(), new SubjectReference($grant->actor_type, $grant->actor_id), new SubjectReference($grant->effective_subject_type, $grant->effective_subject_id), $operation, $grant->expires_at, $operator === null ? null : SubjectReference::fromAuthenticatable($operator)), $grant->getConnection());
    }

    private function invalid(): AuthException
    {
        return new AuthException('impersonation_invalid', 'The impersonation is unavailable or expired.', 403);
    }
}

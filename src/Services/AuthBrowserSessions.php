<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/**
 * Lists and admits authoritative native browser bindings.
 *
 * @api
 */
final readonly class AuthBrowserSessions
{
    public function __construct(private FeatureGate $features, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private SecretHasher $hasher, private PrincipalEligibility $eligibility, private RecentAuthenticationProofs $recent, private AuthAuditRecorder $audits) {}

    public static function bindingKey(string $guardName): string
    {
        return 'nvl-auth.browser.'.hash('sha256', $guardName);
    }

    /**
     * Guard/provider configuration is captured without publishing credentials.
     *
     * @internal
     */
    public static function providerFingerprint(string $guardName): string
    {
        $guard = config('auth.guards.'.$guardName);
        $provider = is_array($guard) && is_string($guard['provider'] ?? null) ? config('auth.providers.'.$guard['provider']) : null;

        return hash('sha256', json_encode([$guardName, $guard, $provider], JSON_THROW_ON_ERROR));
    }

    /** @return LengthAwarePaginator<int, BrowserSession> */
    public function paginate(Authenticatable $subject, string $guardName, int $perPage = 25): LengthAwarePaginator
    {
        $this->features->assertAllowed(AuthFeature::ManagedSessions, FeatureOperation::Read);
        $subject = $this->canonical->resolve($subject);
        $reference = SubjectReference::fromAuthenticatable($subject);

        return BrowserSession::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guardName)->orderByDesc('authenticated_at')->paginate(max(1, min(100, $perPage)));
    }

    public function admit(Authenticatable $subject, string $guardName, #[\SensitiveParameter] string $binding): BrowserSession
    {
        $this->features->assertAllowed(AuthFeature::ManagedSessions, FeatureOperation::Use);
        if (preg_match('/\A[0-9a-f]{64}\z/', $binding) !== 1) {
            throw $this->invalid();
        }
        $subject = $this->canonical->resolve($subject);
        if (! $subject instanceof Model || $subject->getConnection() !== (new BrowserSession)->getConnection()) {
            throw AuthException::invalidConfiguration('Managed sessions require one canonical source.');
        }

        return $subject->getConnection()->transaction(function () use ($subject, $guardName, $binding): BrowserSession {
            $revision = $this->security->lock($subject)->revision;
            $subject = $this->canonical->resolve($subject, true);
            $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $entry = BrowserSession::query()->where('binding_hash', $this->hasher->hash('native-browser-binding', $binding))->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guardName)->lockForUpdate()->first();
            if ($entry === null || $entry->subject_type !== $reference->type || $entry->subject_id !== $reference->identifier || $entry->guard_name !== $guardName || ! $entry->isCurrent($revision) || $entry->provider_hash !== self::providerFingerprint($guardName)) {
                throw $this->invalid();
            }
            if ($entry->last_seen_at->lessThanOrEqualTo(CarbonImmutable::now('UTC')->subSeconds(60))) {
                $entry->last_seen_at = CarbonImmutable::now('UTC');
                $entry->save();
            }

            return $entry;
        }, 3);
    }

    public function revoke(Authenticatable $subject, string $sessionId, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): BrowserSession
    {
        return (new BrowserSession)->getConnection()->transaction(function () use ($subject, $sessionId, $recentProof, $context): BrowserSession {
            $this->recent->consume($subject, $recentProof, RecentAuthenticationPurpose::SessionRevocation, $context);
            $this->security->lock($subject);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $record = BrowserSession::query()->whereKey($sessionId)->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->lockForUpdate()->first();
            if ($record === null) {
                throw $this->invalid();
            }
            $this->revokeFamily($subject, $record->session_family_id, $record->guard_name);
            $record->refresh();
            $this->audits->record('session.revoked', subject: $reference, actor: $subject, metadata: ['browser_session_id' => $record->identifier()]);

            return $record;
        }, 3);
    }

    public function revokeOthers(Authenticatable $subject, string $guardName, string $currentSessionId, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): int
    {
        return (new BrowserSession)->getConnection()->transaction(function () use ($subject, $guardName, $currentSessionId, $recentProof, $context): int {
            $current = $this->admit($subject, $guardName, $context->browserBinding ?? '');
            if ($current->identifier() !== $currentSessionId || $currentSessionId !== $context->browserSessionId || $guardName !== $context->guardName) {
                throw $this->invalid();
            }
            $this->recent->consume($subject, $recentProof, RecentAuthenticationPurpose::SessionRevocation, $context);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $count = BrowserSession::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guardName)->where('session_family_id', '!=', $current->session_family_id)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new BrowserSession)->getConnection(), now())]);
            RememberCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guardName)->where('session_family_id', '!=', $current->session_family_id)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new RememberCredential)->getConnection(), now())]);
            $this->audits->record('session.others_revoked', subject: $reference, actor: $subject, metadata: ['count' => $count, 'current_browser_session_id' => $current->identifier()]);

            return $count;
        }, 3);
    }

    public function revokeAll(Authenticatable $subject, #[\SensitiveParameter] string $recentProof, AuthenticationRequestContext $context): int
    {
        return (new BrowserSession)->getConnection()->transaction(function () use ($subject, $recentProof, $context): int {
            $this->recent->consume($subject, $recentProof, RecentAuthenticationPurpose::SessionRevocation, $context);
            $this->security->lock($subject);
            $reference = SubjectReference::fromAuthenticatable($subject);
            $count = BrowserSession::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new BrowserSession)->getConnection(), now())]);
            RememberCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new RememberCredential)->getConnection(), now())]);
            $this->audits->record('session.all_revoked', subject: $reference, actor: $subject, metadata: ['count' => $count]);

            return $count;
        }, 3);
    }

    private function revokeFamily(Authenticatable $subject, string $family, string $guard): void
    {
        $reference = SubjectReference::fromAuthenticatable($subject);
        BrowserSession::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guard)->where('session_family_id', $family)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new BrowserSession)->getConnection(), now())]);
        RememberCredential::query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->where('guard_name', $guard)->where('session_family_id', $family)->whereNull('revoked_at')->update(['revoked_at' => AuthInstantCast::forQuery((new RememberCredential)->getConnection(), now())]);
    }

    private function invalid(): AuthException
    {
        return new AuthException('browser_session_invalid', 'The browser session is unavailable or expired.', 401);
    }
}

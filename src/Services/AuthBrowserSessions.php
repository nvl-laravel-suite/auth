<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Enums\AuthFeature;
use Nvl\Auth\Enums\FeatureOperation;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/** Lists and admits authoritative native browser bindings. @api */
final readonly class AuthBrowserSessions
{
    public function __construct(private FeatureGate $features, private CanonicalActorResolver $canonical, private PrincipalSecurity $security, private SecretHasher $hasher, private PrincipalEligibility $eligibility) {}

    public static function bindingKey(string $guardName): string
    {
        return 'nvl-auth.browser.'.hash('sha256', $guardName);
    }

    /** Guard/provider configuration is captured without publishing credentials. @internal */
    public static function providerFingerprint(string $guardName): string
    {
        $guard = config('auth.guards.'.$guardName);
        $provider = is_array($guard) && is_string($guard['provider'] ?? null) ? config('auth.providers.'.$guard['provider']) : null;

        return hash('sha256', json_encode([$guard, $provider], JSON_THROW_ON_ERROR));
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
            if ($entry === null || ! $entry->isCurrent($revision) || $entry->provider_hash !== self::providerFingerprint($guardName)) {
                throw $this->invalid();
            }
            if ($entry->last_seen_at->lessThanOrEqualTo(CarbonImmutable::now('UTC')->subSeconds(60))) {
                $entry->last_seen_at = CarbonImmutable::now('UTC');
                $entry->save();
            }

            return $entry;
        }, 3);
    }

    private function invalid(): AuthException
    {
        return new AuthException('browser_session_invalid', 'The browser session is unavailable or expired.', 401);
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Laravel;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\AuthenticationSessions;
use Nvl\Auth\Services\AuthExecutionContext;
use Nvl\Auth\Services\AuthIdentityChallenges;
use Nvl\Auth\Services\AuthImpersonation;
use Nvl\Auth\Services\PrincipalEligibility;
use Nvl\Auth\Services\PrincipalSecurity;
use Nvl\Auth\Services\SecretHasher;
use Nvl\Auth\Support\AuthInstantCast;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Auth\CanonicalActorResolver;

/**
 * Installs only a request-local effective user; Laravel session and recaller identity stay original.
 *
 * @api
 */
final readonly class LaravelImpersonation
{
    public function __construct(private AuthExecutionContext $execution, private AuthenticationSessions $transitions, private AuthManager $auth, private CanonicalActorResolver $canonical, private PrincipalEligibility $eligibility, private AuthImpersonation $grants, private AuthBrowserSessions $browsers, private PrincipalSecurity $security, private SecretHasher $hasher, private AuthIdentityChallenges $challenges) {}

    /** @param array<string, mixed> $data */
    public function start(Authenticatable $target, #[\SensitiveParameter] string $recentProof, array $data, StatefulGuard $guard, Session $session, string $guardName): Impersonation
    {
        $this->transitions->assertCanTransition();
        $actor = $guard->user();
        if ($actor === null || $this->auth->guard($guardName) !== $guard) {
            throw new AuthException('unauthenticated', 'The original authenticated guard is required.', 401);
        }
        $context = $this->context($session, $guardName);
        $grant = $this->grants->start($actor, $target, $recentProof, $data, $context);
        try {
            $this->rotate($actor, $session, $context);
            $session->put('nvl-auth.impersonation.'.$guardName, $grant->identifier());

            return $grant;
        } catch (\Throwable $exception) {
            $this->failClosed($actor, $guard, $session, $context, $grant->identifier());
            throw $exception;
        }
    }

    public function stop(string $impersonationId, StatefulGuard $guard, Session $session, string $guardName): Impersonation
    {
        $this->transitions->assertCanTransition();
        $actor = $guard->user();
        if ($actor === null || $this->auth->guard($guardName) !== $guard) {
            throw new AuthException('unauthenticated', 'The original authenticated guard is required.', 401);
        }
        $context = $this->context($session, $guardName);
        $grant = $this->grants->stop($actor, $impersonationId, $context);
        try {
            $this->rotate($actor, $session, $context);
            $session->forget('nvl-auth.impersonation.'.$guardName);

            return $grant;
        } catch (\Throwable $exception) {
            $this->failClosed($actor, $guard, $session, $context, $grant->identifier());
            throw $exception;
        }
    }

    /** @template TResult
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    public function run(StatefulGuard $guard, Session $session, string $guardName, string $impersonationId, Closure $callback): mixed
    {
        $this->transitions->assertCanTransition();
        $this->execution->assertNativeMutationAllowed();
        if ($this->auth->guard($guardName) !== $guard) {
            throw new AuthException('impersonation_invalid', 'The selected guard does not match.', 403);
        }
        $actor = $guard->user();
        if ($actor === null) {
            throw new AuthException('unauthenticated', 'Authentication is required.', 401);
        }
        $key = AuthBrowserSessions::bindingKey($guardName);
        $id = $session->get($key.'-id');
        $binding = $session->get($key);
        if (! is_string($id) || ! is_string($binding)) {
            throw new AuthException('browser_session_invalid', 'An admitted browser is required.', 401);
        }
        $context = new AuthenticationRequestContext(guardName: $guardName, sessionBinding: $session->getId(), browserSessionId: $id, browserBinding: $binding);
        $entered = false;
        try {
            return $this->execution->run($actor, $impersonationId, $context, function (Authenticatable $target) use ($guard, $callback, &$entered): mixed {
                $entered = true;
                $guard->setUser($target);

                return $callback();
            });
        } catch (AuthException $exception) {
            if (! $entered) {
                try {
                    $this->grants->stop($actor, $impersonationId, $context, 'admission_denied');
                    $this->rotate($actor, $session, $context);
                } catch (\Throwable) {
                    $this->failClosed($actor, $guard, $session, $context, $impersonationId);
                } finally {
                    $session->forget('nvl-auth.impersonation.'.$guardName);
                }
            }
            throw $exception;
        } finally {
            if ($guard instanceof SessionGuard) {
                $guard->forgetUser();
            } else {
                $guard->setUser($actor);
            }
            try {
                $original = $this->canonical->resolve($actor);
                $this->eligibility->assertEligible($original, AuthenticationPurpose::CredentialLogin);
                $guard->setUser($original);
            } catch (\Throwable) {
                try {
                    $guard->logout();
                } finally {
                    if ($guard instanceof SessionGuard) {
                        $guard->forgetUser();
                    } try {
                        $session->invalidate();
                    } finally {
                        $session->regenerateToken();
                    }
                }
            }
        }
    }

    private function context(Session $session, string $guardName): AuthenticationRequestContext
    {
        $key = AuthBrowserSessions::bindingKey($guardName);
        $id = $session->get($key.'-id');
        $binding = $session->get($key);
        if (! is_string($id) || ! is_string($binding)) {
            throw new AuthException('browser_session_invalid', 'An admitted browser is required.', 401);
        }

        return new AuthenticationRequestContext(guardName: $guardName, sessionBinding: $session->getId(), browserSessionId: $id, browserBinding: $binding);
    }

    private function rotate(Authenticatable $actor, Session $session, AuthenticationRequestContext $context): void
    {
        $browser = $this->browsers->admit($actor, $context->guardName ?? '', $context->browserBinding ?? '');
        $browser->getConnection()->transaction(function () use ($actor, $session, $context, $browser): void {
            $revision = $this->security->lock($actor)->revision;
            $browser = BrowserSession::query()->whereKey($browser->identifier())->lockForUpdate()->firstOrFail();
            if (! $browser->isCurrent($revision) || ! hash_equals($browser->binding_hash, $this->hasher->hash('native-browser-binding', $context->browserBinding ?? ''))) {
                throw new AuthException('browser_session_invalid', 'The browser changed during transition.', 401);
            }
            $this->security->lockChallenges($actor);
            $reference = SubjectReference::fromAuthenticatable($actor);
            foreach ($this->challenges->query()->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->whereNull('consumed_at')->whereNull('revoked_at')->lockForUpdate()->get() as $challenge) {
                $facts = $challenge->payload['context'] ?? null;
                if (is_array($facts) && ($facts['guardName'] ?? null) === $context->guardName && ($facts['sessionBinding'] ?? null) === $context->sessionBinding) {
                    $challenge->revoked_at = CarbonImmutable::now();
                    $this->challenges->save($challenge);
                }
            }
            $binding = bin2hex(random_bytes(32));
            $browser->binding_hash = $this->hasher->hash('native-browser-binding', $binding);
            $browser->save();
            if (! $session->regenerate(true)) {
                throw new AuthException('session_transition_failed', 'Browser rotation failed.', 500);
            }
            $session->regenerateToken();
            $session->forget('nvl-auth.credential_login');
            $session->put(AuthBrowserSessions::bindingKey($context->guardName ?? ''), $binding);
        });
    }

    private function failClosed(Authenticatable $actor, StatefulGuard $guard, Session $session, AuthenticationRequestContext $context, string $grantId): void
    {
        $reference = SubjectReference::fromAuthenticatable($actor);
        try {
            BrowserSession::query()->whereKey($context->browserSessionId)->where('subject_type', $reference->type)->where('subject_id', $reference->identifier)->update(['revoked_at' => AuthInstantCast::forQuery((new BrowserSession)->getConnection(), now())]);
            Impersonation::query()->whereKey($grantId)->where('actor_type', $reference->type)->where('actor_id', $reference->identifier)->where('browser_session_id', $context->browserSessionId)->whereNull('stopped_at')->update(['stopped_at' => AuthInstantCast::forQuery((new Impersonation)->getConnection(), now()), 'stop_reason' => 'transition_failed', 'active_session_key' => null]);
        } finally {
            try {
                $guard->logout();
            } finally {
                if ($guard instanceof SessionGuard) {
                    $guard->forgetUser();
                } try {
                    $session->invalidate();
                } finally {
                    $session->regenerateToken();
                }
            }
        }
    }
}

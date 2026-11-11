<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Event;
use Nvl\Auth\Adapters\Laravel\LaravelImpersonation;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Events\ImpersonationChanged;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthExecutionContext;
use Nvl\Auth\Services\AuthImpersonation;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\AuthUsers;
use Nvl\Auth\Tests\Fixtures\TestUser;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

it('denies impersonation by default and binds one expiring grant to its original browser', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    $actor = $this->user('admin@example.test');
    $target = $this->user();
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $binding);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    expect(fn () => app(AuthImpersonation::class)->start($actor, $target, $proof, ['reason' => 'Support ticket'], $context))->toThrow(AuthException::class);
    expect(Impersonation::query()->count())->toBe(0);
    $access = new class implements ImpersonationAccess
    {
        public bool $allowed = true;

        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void
        {
            if (! $this->allowed) {
                throw new AuthException('forbidden', 'Permission removed.', 403);
            }
        }
    };
    app()->instance(ImpersonationAccess::class, $access);
    $grant = app(AuthImpersonation::class)->start($actor, $target, $proof, ['reason' => 'Support ticket', 'durationSeconds' => 60], $context);
    expect($grant->toArray())->not->toHaveKey('reason')->and($guard->id())->toBe($actor->getAuthIdentifier());
    $adapter = app(LaravelImpersonation::class);
    $adapter->run($guard, $store, 'web', $grant->identifier(), function () use ($guard, $target, $actor, $store): void {
        expect($guard->id())->toBe($target->getAuthIdentifier())->and($store->get($guard->getName()))->toBe($actor->getAuthIdentifier());
    });
    expect($guard->id())->toBe($actor->getAuthIdentifier());
    expect(fn () => $adapter->run($guard, $store, 'web', $grant->identifier(), function (): void {
        throw new RuntimeException('business failure');
    }))->toThrow(RuntimeException::class);
    expect($guard->id())->toBe($actor->getAuthIdentifier())->and(app(AuthExecutionContext::class)->facts())->toBeNull();
    $access->allowed = false;
    expect(fn () => $adapter->run($guard, $store, 'web', $grant->identifier(), fn () => null))->toThrow(AuthException::class);
    $access->allowed = true;
    $this->travel(60)->seconds();
    expect(fn () => $adapter->run($guard, $store, 'web', $grant->identifier(), fn () => null))->toThrow(AuthException::class);
});

it('captures original audit attribution and blocks sensitive native operations during an overlay', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    app()->instance(ImpersonationAccess::class, new class implements ImpersonationAccess
    {
        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void {}
    });
    $actor = $this->user('admin@example.test');
    $target = $this->user();
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $binding);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    $grant = app(AuthImpersonation::class)->start($actor, $target, $proof, ['reason' => 'Support ticket'], $context);
    $deferred = null;
    app(LaravelImpersonation::class)->run($guard, $store, 'web', $grant->identifier(), function () use ($guard, $target, &$deferred): void {
        expect(fn () => app(AuthUsers::class)->updateProfile($target, ['name' => 'Forbidden']))->toThrow(AuthException::class, 'while impersonating');
        expect(fn () => app(AuthTokens::class)->create($target, ['name' => 'Forbidden token']))->toThrow(AuthException::class, 'while impersonating');
        app(AuthAuditRecorder::class)->record('business.support_read', actor: $guard->user());
        expect(fn () => app(AuthAuditRecorder::class)->record('business.forged', actor: $guard->user(), metadata: ['impersonation_id' => 'forged']))->toThrow(AuthException::class);
        $deferred = app(Nvl\Auth\Services\AuthAuditRecorder::class)->prepare('business.deferred', actor: $guard->user());
    });
    $deferred();
    foreach (['business.support_read', 'business.deferred'] as $action) {
        $audit = AuthAudit::query()->where('action', $action)->sole();
        expect($audit->actor_id)->toBe((string) $actor->getKey())->and($audit->metadata['effective_subject_id'])->toBe((string) $target->getKey())->and($audit->metadata['impersonation_id'])->toBe($grant->identifier());
    }
});

it('rotates native browser binding through explicit start and stop transport without persisting a target login', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    app()->instance(ImpersonationAccess::class, new class implements ImpersonationAccess
    {
        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void {}
    });
    $actor = $this->user('admin@example.test');
    $target = $this->user();
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $key = AuthBrowserSessions::bindingKey('web');
    $old = $store->get($key);
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $old);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $old);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    $adapter = app(LaravelImpersonation::class);
    $grant = $adapter->start($target, $proof, ['reason' => 'Support ticket'], $guard, $store, 'web');
    expect($store->get($key))->not->toBe($old)->and($guard->id())->toBe($actor->getAuthIdentifier());
    expect(fn () => app(AuthBrowserSessions::class)->admit($actor, 'web', $old))->toThrow(AuthException::class);
    $adapter->run($guard, $store, 'web', $grant->identifier(), fn () => expect($guard->id())->toBe($target->getAuthIdentifier()));
    $revoked = app(AuthImpersonation::class)->revoke($actor, $grant->identifier(), 'Support permission withdrawn');
    expect($revoked->stop_reason)->toBe('administrative');
    $beforeStop = $store->get($key);
    $adapter->stop($grant->identifier(), $guard, $store, 'web');
    expect($store->get($key))->not->toBe($beforeStop)->and($grant->refresh()->stopped_at)->not->toBeNull()->and($store->get($guard->getName()))->toBe($actor->getAuthIdentifier());
});

it('commits expiry at the exact deadline and rejects an outer transaction before spending start proof', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    app()->instance(ImpersonationAccess::class, new class implements ImpersonationAccess
    {
        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void {}
    });
    $actor = $this->user('admin@example.test');
    $target = $this->user();
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $binding);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    $service = app(AuthImpersonation::class);
    expect(fn () => $actor->getConnection()->transaction(fn () => $service->start($actor, $target, $proof, ['reason' => 'Support'], $context)))->toThrow(AuthException::class);
    expect(Impersonation::query()->count())->toBe(0);
    $grant = $service->start($actor, $target, $proof, ['reason' => 'Support', 'durationSeconds' => 60], $context);
    $this->travelTo($grant->expires_at);
    expect(fn () => $service->admit($actor, $grant->identifier(), $context))->toThrow(AuthException::class);
    expect($grant->refresh()->stop_reason)->toBe('expired');
});

/**
 * Log an administrator into a managed browser and return the facts an impersonation start needs.
 *
 * @return array{actor: TestUser, target: TestUser, store: Session, guard: StatefulGuard, context: AuthenticationRequestContext, proof: string}
 */
function impersonationScenario(TestUser $actor, TestUser $target): array
{
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    app()->instance(ImpersonationAccess::class, new class implements ImpersonationAccess
    {
        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void {}
    });
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $binding);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();

    return ['actor' => $actor, 'target' => $target, 'store' => $store, 'guard' => $guard, 'context' => $context, 'proof' => $proof];
}

it('refuses self impersonation and a nested start from inside an overlay', function (): void {
    ['actor' => $actor, 'target' => $target, 'store' => $store, 'guard' => $guard, 'context' => $context, 'proof' => $proof] = impersonationScenario($this->user('admin@example.test'), $this->user());
    $service = app(AuthImpersonation::class);

    expect(fn () => $service->start($actor, $actor, $proof, ['reason' => 'Self'], $context))->toThrow(AuthException::class, 'unavailable or expired')
        ->and(Impersonation::query()->count())->toBe(0);

    $grant = $service->start($actor, $target, $proof, ['reason' => 'Support ticket'], $context);
    $third = $this->user('third@example.test');
    app(LaravelImpersonation::class)->run($guard, $store, 'web', $grant->identifier(), function () use ($service, $target, $third, $proof, $context, $grant): void {
        expect(fn () => $service->start($target, $third, $proof, ['reason' => 'Nested'], $context))->toThrow(AuthException::class, 'while impersonating')
            ->and(fn () => $service->stop($target, $grant->identifier(), $context))->toThrow(AuthException::class, 'while impersonating');
    });
    expect(fn () => $service->start($actor, $third, $proof, ['reason' => 'Second'], $context))->toThrow(AuthException::class, 'already has an active impersonation')
        ->and(Impersonation::query()->count())->toBe(1);
});

it('regenerates the session on enter and leave and ends the overlay once the impersonator is contained', function (): void {
    ['actor' => $actor, 'target' => $target, 'store' => $store, 'guard' => $guard, 'proof' => $proof] = impersonationScenario($this->user('admin@example.test'), $this->user());
    $adapter = app(LaravelImpersonation::class);
    $before = $store->getId();
    $grant = $adapter->start($target, $proof, ['reason' => 'Support ticket'], $guard, $store, 'web');
    $entered = $store->getId();
    expect($entered)->not->toBe($before)->and($store->get('nvl-auth.impersonation.web'))->toBe($grant->identifier());

    $actor->forceFill(['is_active' => false])->save();
    $reached = false;
    expect(function () use ($adapter, $guard, $store, $grant, &$reached): void {
        $adapter->run($guard, $store, 'web', $grant->identifier(), function () use (&$reached): void {
            $reached = true;
        });
    })->toThrow(AuthException::class);
    expect($reached)->toBeFalse()->and($guard->check())->toBeFalse()->and($grant->refresh()->stopped_at)->not->toBeNull();
});

it('leaves through stop with a regenerated session and the original principal restored', function (): void {
    ['actor' => $actor, 'target' => $target, 'store' => $store, 'guard' => $guard, 'proof' => $proof] = impersonationScenario($this->user('admin@example.test'), $this->user());
    $adapter = app(LaravelImpersonation::class);
    $grant = $adapter->start($target, $proof, ['reason' => 'Support ticket'], $guard, $store, 'web');
    $entered = $store->getId();
    $adapter->stop($grant->identifier(), $guard, $store, 'web');

    expect($store->getId())->not->toBe($entered)
        ->and($store->has('nvl-auth.impersonation.web'))->toBeFalse()
        ->and($guard->id())->toBe($actor->getAuthIdentifier())
        ->and(fn () => $adapter->run($guard, $store, 'web', $grant->identifier(), fn () => null))->toThrow(AuthException::class);
});

it('audits every impersonation ending with the impersonator and the impersonated principal', function (): void {
    ['actor' => $actor, 'target' => $target, 'context' => $context, 'proof' => $proof] = impersonationScenario($this->user('admin@example.test'), $this->user());
    $service = app(AuthImpersonation::class);
    $expired = $service->start($actor, $target, $proof, ['reason' => 'First ticket', 'durationSeconds' => 60], $context);
    $this->travel(61)->seconds();
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    $revoked = $service->start($actor, $target, $proof, ['reason' => 'Second ticket'], $context);
    $operator = $this->user('operator@example.test');
    $service->revoke($operator, $revoked->identifier(), 'Support permission withdrawn');

    $expiry = AuthAudit::query()->where('action', 'impersonation.expired')->sole();
    $revocation = AuthAudit::query()->where('action', 'impersonation.revoked')->sole();
    expect($expired->refresh()->stop_reason)->toBe('expired')
        ->and($expiry->metadata['grant_id'])->toBe($expired->identifier())
        ->and($expiry->actor_id)->toBe((string) $actor->getKey())
        ->and($expiry->subject_id)->toBe((string) $target->getKey())
        ->and($revocation->actor_id)->toBe((string) $operator->getKey())
        ->and($revocation->subject_id)->toBe((string) $target->getKey())
        ->and($revocation->metadata['impersonator_id'])->toBe((string) $actor->getKey())
        ->and($revocation->metadata['impersonator_type'])->toBe($actor->getMorphClass())
        ->and(AuthAudit::query()->where('action', 'impersonation.granted')->count())->toBe(2);
});

it('audits the compensating stop when the browser transition fails after the grant is created', function (): void {
    ['actor' => $actor, 'target' => $target, 'store' => $store, 'guard' => $guard, 'proof' => $proof] = impersonationScenario($this->user('admin@example.test'), $this->user());
    Event::listen(ImpersonationChanged::class, static function (ImpersonationChanged $event): void {
        if ($event->operation === 'granted') {
            BrowserSession::query()->update(['revoked_at' => now()]);
        }
    });

    expect(fn () => app(LaravelImpersonation::class)->start($target, $proof, ['reason' => 'Support ticket'], $guard, $store, 'web'))->toThrow(AuthException::class);

    $grant = Impersonation::query()->sole();
    $stopped = AuthAudit::query()->where('action', 'impersonation.stopped')->sole();
    expect($grant->stop_reason)->toBe('transition_failed')
        ->and($grant->active_session_key)->toBeNull()
        ->and($stopped->metadata['reason'])->toBe('transition_failed')
        ->and($stopped->actor_id)->toBe((string) $actor->getKey())
        ->and($stopped->subject_id)->toBe((string) $target->getKey())
        ->and($guard->check())->toBeFalse()
        ->and($store->has('nvl-auth.impersonation.web'))->toBeFalse();
});

<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Adapters\Laravel\LaravelImpersonation;
use Nvl\Auth\Contracts\AuthAuditRecorder;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\AuthAudit;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthExecutionContext;
use Nvl\Auth\Services\AuthImpersonation;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Services\AuthTokens;
use Nvl\Auth\Services\AuthUsers;
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

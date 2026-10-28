<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Adapters\Laravel\LaravelImpersonation;
use Nvl\Auth\Contracts\ImpersonationAccess;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Services\AuthBrowserSessions;
use Nvl\Auth\Services\Authentication;
use Nvl\Auth\Services\AuthImpersonation;
use Nvl\Auth\Services\AuthReauthentication;
use Nvl\Auth\Tests\Fixtures\AuthOwnerScenario;
use Nvl\Auth\ValueObjects\AuthenticationRequestContext;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

it('uses target owner admission temporarily and refuses grant reuse after owner switching', function (): void {
    config(['nvl-auth.features.managed_sessions.enabled' => true, 'nvl-auth.features.impersonation.enabled' => true]);
    app()->instance(ImpersonationAccess::class, new class implements ImpersonationAccess
    {
        public function assertAllowed(Authenticatable $actor, Authenticatable $target, ?OwnerReference $owner): void {}
    });
    $scenario = new AuthOwnerScenario;
    $actor = $this->user('admin@example.test');
    $target = $this->user();
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($actor), true);
    $scenario->member($scenario->a(), SubjectReference::fromAuthenticatable($target));
    $store = app('session.store');
    $guard = auth()->guard('web');
    app(Authentication::class)->login(['identifier' => $actor->email, 'password' => 'correct-password'], [], $guard, $store);
    $binding = $store->get(AuthBrowserSessions::bindingKey('web'));
    $browser = app(AuthBrowserSessions::class)->admit($actor, 'web', $binding);
    $context = new AuthenticationRequestContext(guardName: 'web', sessionBinding: $store->getId(), browserSessionId: $browser->identifier(), browserBinding: $binding);
    $proof = app(AuthReauthentication::class)->confirm($actor, ['password' => 'correct-password'], RecentAuthenticationPurpose::ImpersonationStart, $context)->reveal();
    $grant = $scenario->run($scenario->a(), fn () => app(AuthImpersonation::class)->start($actor, $target, $proof, ['reason' => 'Owner support'], $context));
    $scenario->run($scenario->a(), function () use ($guard, $store, $grant, $target): void {
        $before = app(OwnershipContext::class)->snapshot();
        app(LaravelImpersonation::class)->run($guard, $store, 'web', $grant->identifier(), function () use ($target): void {
            expect(app(OwnershipContext::class)->snapshot()->principal['id'])->toBe((string) $target->getAuthIdentifier());
        });
        expect(app(OwnershipContext::class)->snapshot())->toEqual($before);
    });
    expect(fn () => $scenario->run($scenario->b(), fn () => app(LaravelImpersonation::class)->run($guard, $store, 'web', $grant->identifier(), fn () => null)))->toThrow(AuthException::class);
    expect($guard->id())->toBe($actor->getAuthIdentifier());
});

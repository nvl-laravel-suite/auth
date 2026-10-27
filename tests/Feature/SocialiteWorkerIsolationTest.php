<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Two\InvalidStateException;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Services\AuthSocialIdentities;
use Nvl\Auth\Tests\Fixtures\WorkerProviderFactory;

it('does not reuse a provider user across two worker requests', function (): void {
    $this->app->scoped(SocialIdentityProviderFactory::class, fn (): SocialIdentityProviderFactory => new WorkerProviderFactory);
    $factory = $this->app->make(SocialIdentityProviderFactory::class);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $firstRequest = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $firstRequest->setLaravelSession($session);
    $this->app->instance('request', $firstRequest);
    $first = $factory->make('github');
    expect($first->user('github', null)->providerUserId)->toBe('subject-a');
    $secondRequest = Request::create('/callback', 'GET', ['state' => 'wrong']);
    $secondRequest->setLaravelSession(new Store('session', new ArraySessionHandler(120)));
    $this->app->instance('request', $secondRequest);
    $second = $factory->make('github');
    expect($second)->not->toBe($first);
    expect(fn () => $second->user('github', null))->toThrow(InvalidStateException::class);
});

it('rejects invalid state across requests through one retained native service', function (): void {
    config()->set('nvl-auth.features.social_identities.enabled', true);
    config()->set('nvl-auth.features.social_identities.settings.providers.github', ['scopes' => [], 'parameters' => []]);
    $this->app->instance(SocialIdentityProviderFactory::class, new WorkerProviderFactory);
    $service = $this->app->make(AuthSocialIdentities::class);
    $subject = $this->user();
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $firstRequest = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $firstRequest->setLaravelSession($session);
    $this->app->instance('request', $firstRequest);
    expect($service->completeAuthorization('github', $subject)->subject_id)->toBe((string) $subject->getKey());

    $secondRequest = Request::create('/callback', 'GET', ['state' => 'wrong']);
    $secondRequest->setLaravelSession(new Store('session', new ArraySessionHandler(120)));
    $this->app->instance('request', $secondRequest);
    try {
        $service->completeAuthorization('github', $subject);
        $this->fail('The invalid state must be rejected.');
    } catch (AuthException $exception) {
        expect($exception->errorCode)->toBe('social_authorization_failed');
    }
    expect(SocialIdentity::query()->count())->toBe(1);
});

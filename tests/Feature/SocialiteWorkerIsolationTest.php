<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Two\InvalidStateException;
use Nvl\Auth\Contracts\SocialIdentityProviderFactory;
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

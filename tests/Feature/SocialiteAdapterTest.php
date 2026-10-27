<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\Testing\SocialiteFake;
use Laravel\Socialite\Two\GithubProvider;
use Laravel\Socialite\Two\GoogleProvider;
use Laravel\Socialite\Two\User;
use Nvl\Auth\Adapters\Socialite\GoogleEmailVerification;
use Nvl\Auth\Adapters\Socialite\SocialiteIdentityProvider;
use Nvl\Auth\Exceptions\AuthException;

it('acquires Socialite identity claims without retaining OAuth credentials', function (): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('google', User::fake([
        'id' => 'google-123',
        'email' => 'social@example.test',
        'token' => 'must-not-leak',
        'refreshToken' => 'must-not-leak-either',
        'email_verified' => true,
    ]));
    $adapter = new SocialiteIdentityProvider($socialite->driver('google'), 'google', new GoogleEmailVerification);

    expect($adapter->redirectUrl('google', null, [], []))
        ->toBe('https://socialite.fake/google/authorize');

    $identity = $adapter->user('google', null);

    expect($identity->providerUserId)->toBe('google-123')
        ->and($identity->email)->toBe('social@example.test')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->emailVerificationSource)->toBe('google.userinfo.email_verified')
        ->and($identity->profile)->not->toHaveKeys(['token', 'refreshToken']);
});

it('fails closed when Socialite cannot prove a returned email address', function (): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('github', User::fake([
        'id' => 'github-123',
        'email' => 'unverified@example.test',
        'email_verified' => false,
    ]));

    expect((new SocialiteIdentityProvider($socialite->driver('github'), 'github'))->user('github', null)->emailVerified)->toBeFalse();
});

it('preserves exact Socialite identifiers', function (mixed $id, string $expected): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('google', User::fake(['id' => $id, 'email' => null]));

    expect((new SocialiteIdentityProvider($socialite->driver('google'), 'google'))->user('google', null)->providerUserId)->toBe($expected);
})->with([[123, '123'], ['000123', '000123']]);

it('does not treat arbitrary GitHub account claims as email proof', function (): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('github', User::fake(['id' => '123', 'email' => 'user@example.test', 'verified' => true, 'email_verified' => true]));

    expect((new SocialiteIdentityProvider($socialite->driver('github'), 'github'))->user('github', null)->emailVerified)->toBeFalse();
});

it('rejects invalid provider identifiers', function (mixed $id): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('google', User::fake(['id' => $id, 'email' => null]));

    expect(fn () => (new SocialiteIdentityProvider($socialite->driver('google'), 'google'))->user('google', null))
        ->toThrow(AuthException::class);
})->with([null, '', 1.5, new stdClass]);

it('maps the real GitHub SDK verified-primary email response', function (): void {
    $request = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $request->setLaravelSession($session);
    $responses = new MockHandler([
        new Response(200, [], '{"access_token":"private-token"}'),
        new Response(200, [], file_get_contents(__DIR__.'/../Fixtures/Socialite/github-user.json')),
        new Response(200, [], file_get_contents(__DIR__.'/../Fixtures/Socialite/github-emails.json')),
    ]);
    $driver = new GithubProvider($request, 'client', 'secret', 'https://example.test/callback');
    $driver->setHttpClient(new Client(['handler' => HandlerStack::create($responses)]));
    $identity = (new SocialiteIdentityProvider($driver, 'github'))->user('github', null);

    expect($identity->providerUserId)->toBe('123')
        ->and($identity->email)->toBe('primary@example.test')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->emailVerificationSource)->toBe('github.user.emails.verified_primary')
        ->and(json_encode($identity))->not->toContain('private-token');
});

it('maps the real Google SDK userinfo verification claim', function (): void {
    $request = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $request->setLaravelSession($session);
    $responses = new MockHandler([
        new Response(200, [], '{"access_token":"private-token"}'),
        new Response(200, [], file_get_contents(__DIR__.'/../Fixtures/Socialite/google-user.json')),
    ]);
    $driver = new GoogleProvider($request, 'client', 'secret', 'https://example.test/callback');
    $driver->setHttpClient(new Client(['handler' => HandlerStack::create($responses)]));
    $identity = (new SocialiteIdentityProvider($driver, 'google'))->user('google', null);

    expect($identity->providerUserId)->toBe('000123')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->emailVerificationSource)->toBe('google.userinfo.email_verified')
        ->and(json_encode($identity))->not->toContain('private-token');
});

it('never promotes a false or missing Google verification claim', function (array $claims): void {
    $user = User::fake(['id' => 'subject', 'email' => 'google@example.test', ...$claims]);
    expect((new GoogleEmailVerification)->verification($user)['verified'])->toBeFalse();
})->with([[['email_verified' => false]], [['email_verified' => 'true']], [[]]]);

it('does not trust GitHub account email without the verified-primary scope', function (): void {
    $request = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $request->setLaravelSession($session);
    $responses = new MockHandler([
        new Response(200, [], '{"access_token":"private-token"}'),
        new Response(200, [], file_get_contents(__DIR__.'/../Fixtures/Socialite/github-user.json')),
    ]);
    $driver = new GithubProvider($request, 'client', 'secret', 'https://example.test/callback');
    $driver->setScopes(['read:user']);
    $driver->setHttpClient(new Client(['handler' => HandlerStack::create($responses)]));
    $identity = (new SocialiteIdentityProvider($driver, 'github'))->user('github', null);
    expect($identity->email)->toBe('public@example.test')->and($identity->emailVerified)->toBeFalse();
});

it('requires a verified primary GitHub email', function (string $emails): void {
    $request = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $request->setLaravelSession($session);
    $responses = new MockHandler([
        new Response(200, [], '{"access_token":"private-token"}'),
        new Response(200, [], file_get_contents(__DIR__.'/../Fixtures/Socialite/github-user.json')),
        new Response(200, [], $emails),
    ]);
    $driver = new GithubProvider($request, 'client', 'secret', 'https://example.test/callback');
    $driver->setHttpClient(new Client(['handler' => HandlerStack::create($responses)]));
    $identity = (new SocialiteIdentityProvider($driver, 'github'))->user('github', null);
    expect($identity->email)->toBeNull()->and($identity->emailVerified)->toBeFalse();
})->with([
    '[{"email":"unverified@example.test","primary":true,"verified":false}]',
    '[{"email":"secondary@example.test","primary":false,"verified":true}]',
    '[]',
]);

it('surfaces a provider network failure without manufacturing an identity', function (): void {
    $request = Request::create('/callback', 'GET', ['state' => 'state-a', 'code' => 'code-a']);
    $session = new Store('session', new ArraySessionHandler(120));
    $session->put('state', 'state-a');
    $request->setLaravelSession($session);
    $responses = new MockHandler([new Response(503)]);
    $driver = new GoogleProvider($request, 'client', 'secret', 'https://example.test/callback');
    $driver->setHttpClient(new Client(['handler' => HandlerStack::create($responses)]));
    expect(fn () => (new SocialiteIdentityProvider($driver, 'google'))->user('google', null))->toThrow(ServerException::class);
});

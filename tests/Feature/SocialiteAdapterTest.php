<?php

declare(strict_types=1);

use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\Testing\SocialiteFake;
use Laravel\Socialite\Two\User;
use Nvl\Auth\Adapters\Socialite\SocialiteIdentityProvider;

it('acquires Socialite identity claims without retaining OAuth credentials', function (): void {
    $factory = Mockery::mock(Factory::class);
    $socialite = new SocialiteFake($factory);
    $socialite->fake('github', User::fake([
        'id' => 'github-123',
        'email' => 'social@example.test',
        'token' => 'must-not-leak',
        'refreshToken' => 'must-not-leak-either',
    ]));
    $adapter = new SocialiteIdentityProvider($socialite);

    expect($adapter->redirectUrl('github', null, [], []))
        ->toBe('https://socialite.fake/github/authorize');

    $identity = $adapter->user('github', null);

    expect($identity->providerUserId)->toBe('github-123')
        ->and($identity->email)->toBe('social@example.test')
        ->and($identity->profile)->not->toHaveKeys(['token', 'refreshToken']);
});

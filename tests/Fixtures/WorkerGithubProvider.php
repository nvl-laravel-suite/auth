<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Laravel\Socialite\Two\GithubProvider;

/** Exercises real Socialite state and user caching without network calls. */
final class WorkerGithubProvider extends GithubProvider
{
    public function getAccessTokenResponse($code): array
    {
        return ['access_token' => 'token-a'];
    }

    protected function getUserByToken($token): array
    {
        return ['id' => 'subject-a', 'node_id' => 'node-a', 'login' => 'subject-a', 'avatar_url' => null];
    }
}

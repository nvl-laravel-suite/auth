<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Nvl\Auth\Models\PersonalAccessToken;
use Nvl\Auth\Models\User;

/** @extends Factory<PersonalAccessToken> */
final class PersonalAccessTokenFactory extends Factory
{
    /** @var class-string<PersonalAccessToken> */
    protected $model = PersonalAccessToken::class;

    public function definition(): array
    {
        return [
            'tokenable_type' => User::class,
            'tokenable_id' => User::factory(),
            'name' => 'nvl-auth:test-token',
            'token' => hash('sha256', Str::random(80)),
            'abilities' => ['*'],
        ];
    }
}

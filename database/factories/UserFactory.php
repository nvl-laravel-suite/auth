<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Nvl\Auth\Models\User;

/**
 * Builds package-owned principals for consumers and package tests.
 *
 * @extends Factory<User>
 */
final class UserFactory extends Factory
{
    /** @var class-string<User> */
    protected $model = User::class;

    /**
     * Define a conventional enabled principal.
     */
    public function definition(): array
    {
        return [
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'email_verified_at' => now(),
            'password' => Hash::make('password'),
            'is_active' => true,
            'locale' => 'en',
            'timezone' => 'UTC',
            'remember_token' => Str::random(10),
        ];
    }

    /**
     * Mark the principal's email as unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn (): array => ['email_verified_at' => null]);
    }

    /**
     * Mark the principal as disabled.
     */
    public function disabled(): static
    {
        return $this->state(fn (): array => ['is_active' => false]);
    }
}

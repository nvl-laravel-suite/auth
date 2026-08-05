<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\Challenge;

/**
 * Builds one-time authentication challenges.
 *
 * @extends Factory<Challenge>
 */
final class ChallengeFactory extends Factory
{
    /** @var class-string<Challenge> */
    protected $model = Challenge::class;

    /**
     * Define a valid challenge record.
     */
    public function definition(): array
    {
        return [
            'type' => 'security_code',
            'purpose' => 'login',
            'recipient_hash' => hash('sha256', fake()->safeEmail()),
            'secret_hash' => hash('sha256', fake()->uuid()),
            'payload' => [],
            'attempts' => 0,
            'max_attempts' => 5,
            'expires_at' => now()->addMinutes(10),
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\PendingEmailChange;
use Nvl\Auth\Models\User;

/** @extends Factory<PendingEmailChange> */
final class PendingEmailChangeFactory extends Factory
{
    protected $model = PendingEmailChange::class;

    /** @return array<string, mixed> */
    public function definition(): array
    {
        return ['subject_type' => 'users', 'subject_id' => User::factory(), 'new_email' => fake()->safeEmail(), 'email_hash' => hash('sha256', fake()->uuid()), 'token_hash' => hash('sha256', fake()->uuid()), 'security_revision' => 1, 'active_key' => hash('sha256', fake()->uuid()), 'context' => [], 'expires_at' => now()->addHour()];
    }
}

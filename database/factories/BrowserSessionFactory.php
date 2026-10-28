<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\User;

/** Creates registry metadata without an authenticating bearer.
 * @extends Factory<BrowserSession>
 */
final class BrowserSessionFactory extends Factory
{
    protected $model = BrowserSession::class;

    /** @return array<model-property<BrowserSession>, mixed> */
    public function definition(): array
    {
        return ['subject_type' => 'users', 'subject_id' => User::factory(), 'guard_name' => 'web', 'provider_hash' => hash('sha256', fake()->uuid()), 'binding_hash' => hash('sha256', fake()->uuid()), 'security_revision' => 1, 'session_family_id' => (string) Str::uuid(), 'method' => 'password', 'assurance' => ['factors' => ['primary']], 'authenticated_at' => now(), 'last_seen_at' => now(), 'absolute_expires_at' => now()->addHours(12)];
    }
}

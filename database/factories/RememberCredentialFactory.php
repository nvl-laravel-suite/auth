<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Nvl\Auth\Models\RememberCredential;
use Nvl\Auth\Models\User;

/** Metadata fixture without a usable plaintext credential.
 * @extends Factory<RememberCredential>
 */
final class RememberCredentialFactory extends Factory
{
    protected $model = RememberCredential::class;

    /** @return array<model-property<RememberCredential>, mixed> */
    public function definition(): array
    {
        return ['selector' => bin2hex(random_bytes(32)), 'secret_hash' => hash('sha256', fake()->uuid()), 'subject_type' => 'users', 'subject_id' => User::factory(), 'guard_name' => 'web', 'provider_hash' => hash('sha256', fake()->uuid()), 'session_family_id' => (string) Str::uuid(), 'security_revision' => 1, 'absolute_expires_at' => now()->addDays(30)];
    }
}

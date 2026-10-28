<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\BrowserSession;
use Nvl\Auth\Models\Impersonation;
use Nvl\Auth\Models\User;

/** Inactive metadata fixture, never browser authority.
 * @extends Factory<Impersonation>
 */
final class ImpersonationFactory extends Factory
{
    protected $model = Impersonation::class;

    /** @return array<model-property<Impersonation>, mixed> */
    public function definition(): array
    {
        return ['actor_type' => 'users', 'actor_id' => User::factory(), 'effective_subject_type' => 'users', 'effective_subject_id' => User::factory(), 'browser_session_id' => BrowserSession::factory(), 'guard_name' => 'web', 'actor_revision' => 1, 'target_revision' => 1, 'reason' => 'Support fixture', 'started_at' => now(), 'expires_at' => now()->addMinutes(15)];
    }
}

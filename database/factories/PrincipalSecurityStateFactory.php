<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\PrincipalSecurityState;
use Nvl\Auth\Models\User;

/** Initial security epochs for canonical package principals.
 * @extends Factory<PrincipalSecurityState>
 *
 * @internal
 */
final class PrincipalSecurityStateFactory extends Factory
{
    protected $model = PrincipalSecurityState::class;

    /** @return array<model-property<PrincipalSecurityState>, mixed> */
    public function definition(): array
    {
        return ['subject_type' => 'users', 'subject_id' => User::factory(), 'revision' => 1];
    }
}

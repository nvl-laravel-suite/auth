<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\Passkey;

/**
 * Builds verified passkey credential records.
 *
 * @extends Factory<Passkey>
 */
final class PasskeyFactory extends Factory
{
    /** @var class-string<Passkey> */
    protected $model = Passkey::class;

    /**
     * Define a valid passkey credential.
     */
    public function definition(): array
    {
        $credentialId = fake()->uuid();

        return [
            'subject_type' => 'users',
            'subject_id' => (string) fake()->numberBetween(1, 100000),
            'name' => fake()->word(),
            'credential_id' => $credentialId,
            'credential_id_hash' => hash('sha256', $credentialId),
            'public_key' => fake()->sha256(),
            'user_handle' => fake()->uuid(),
            'signature_counter' => 0,
            'transports' => ['internal'],
            'backup_eligible' => false,
            'backed_up' => false,
        ];
    }
}

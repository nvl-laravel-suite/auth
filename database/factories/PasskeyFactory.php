<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use InvalidArgumentException;
use Nvl\Auth\Models\Passkey;
use Nvl\Auth\Models\User;

/**
 * Builds verified passkey credential records.
 *
 * @api
 *
 * @extends Factory<Passkey>
 */
final class PasskeyFactory extends Factory
{
    /** @var class-string<Passkey> */
    protected $model = Passkey::class;

    /**
     * Define a valid passkey credential.
     *
     * @return array<model-property<Passkey>, mixed>
     */
    public function definition(): array
    {
        $credentialId = fake()->uuid();

        return [
            'subject_type' => 'users',
            'subject_id' => User::factory(),
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

    /** Associate a persisted package principal using Auth's native subject alias.
     *
     * @api
     */
    public function forSubject(User $subject): static
    {
        if (! $subject->exists || $subject->getKey() === null
            || $subject->getConnection() !== (new Passkey)->getConnection()) {
            throw new InvalidArgumentException('Auth subject fixtures require a persisted principal on their connection.');
        }

        return $this->state(['subject_type' => 'users', 'subject_id' => $subject->getKey()]);
    }
}

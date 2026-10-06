<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use InvalidArgumentException;
use Nvl\Auth\Models\SocialIdentity;
use Nvl\Auth\Models\User;

/**
 * Builds external social-identity links without OAuth credentials.
 *
 * @api
 *
 * @extends Factory<SocialIdentity>
 */
final class SocialIdentityFactory extends Factory
{
    /** @var class-string<SocialIdentity> */
    protected $model = SocialIdentity::class;

    /**
     * Define a valid social identity.
     *
     * @return array<model-property<SocialIdentity>, mixed>
     */
    public function definition(): array
    {
        $providerUserId = fake()->uuid();

        return [
            'subject_type' => 'users',
            'subject_id' => User::factory(),
            'provider' => 'github',
            'provider_user_id' => $providerUserId,
            'provider_user_id_hash' => hash('sha256', $providerUserId),
            'email' => fake()->safeEmail(),
            'profile' => [],
        ];
    }

    /** Associate a persisted package principal using Auth's native subject alias.
     *
     * @api
     */
    public function forSubject(User $subject): static
    {
        if (! $subject->exists || $subject->getKey() === null
            || $subject->getConnection() !== (new SocialIdentity)->getConnection()) {
            throw new InvalidArgumentException('Auth subject fixtures require a persisted principal on their connection.');
        }

        return $this->state(['subject_type' => 'users', 'subject_id' => $subject->getKey()]);
    }
}

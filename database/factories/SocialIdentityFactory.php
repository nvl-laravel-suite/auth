<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\SocialIdentity;

/**
 * Builds external social-identity links without OAuth credentials.
 *
 * @extends Factory<SocialIdentity>
 */
final class SocialIdentityFactory extends Factory
{
    /** @var class-string<SocialIdentity> */
    protected $model = SocialIdentity::class;

    /**
     * Define a valid social identity.
     */
    public function definition(): array
    {
        $providerUserId = fake()->uuid();

        return [
            'subject_type' => 'users',
            'subject_id' => (string) fake()->numberBetween(1, 100000),
            'provider' => 'github',
            'provider_user_id' => $providerUserId,
            'provider_user_id_hash' => hash('sha256', $providerUserId),
            'email' => fake()->safeEmail(),
            'profile' => [],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\TotpCredential;

/**
 * Builds confirmed TOTP credentials.
 *
 * @extends Factory<TotpCredential>
 */
final class TotpCredentialFactory extends Factory
{
    /** @var class-string<TotpCredential> */
    protected $model = TotpCredential::class;

    /**
     * Define a valid TOTP credential.
     */
    public function definition(): array
    {
        return [
            'subject_type' => 'users',
            'subject_id' => (string) fake()->numberBetween(1, 100000),
            'secret' => 'JBSWY3DPEHPK3PXP',
            'algorithm' => 'sha1',
            'digits' => 6,
            'period' => 30,
            'allowed_drift' => 1,
            'confirmed_at' => now(),
        ];
    }
}

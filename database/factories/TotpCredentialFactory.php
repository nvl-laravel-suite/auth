<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use InvalidArgumentException;
use Nvl\Auth\Models\TotpCredential;
use Nvl\Auth\Models\User;

/**
 * Builds confirmed TOTP credentials.
 *
 * @api
 *
 * @extends Factory<TotpCredential>
 */
final class TotpCredentialFactory extends Factory
{
    /** @var class-string<TotpCredential> */
    protected $model = TotpCredential::class;

    /**
     * Define a valid TOTP credential.
     *
     * @return array<model-property<TotpCredential>, mixed>
     */
    public function definition(): array
    {
        return [
            'subject_type' => 'users',
            'subject_id' => User::factory(),
            'secret' => 'JBSWY3DPEHPK3PXP',
            'algorithm' => 'sha1',
            'digits' => 6,
            'period' => 30,
            'allowed_drift' => 1,
            'confirmed_at' => now(),
        ];
    }

    /** Associate a persisted package principal using Auth's native subject alias.
     *
     * @api
     */
    public function forSubject(User $subject): static
    {
        if (! $subject->exists || $subject->getKey() === null
            || $subject->getConnection() !== (new TotpCredential)->getConnection()) {
            throw new InvalidArgumentException('Auth subject fixtures require a persisted principal on their connection.');
        }

        return $this->state(['subject_type' => 'users', 'subject_id' => $subject->getKey()]);
    }
}

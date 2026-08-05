<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use Nvl\Auth\Models\RecoveryCode;

/**
 * Builds hashed one-time recovery-code records.
 *
 * @extends Factory<RecoveryCode>
 */
final class RecoveryCodeFactory extends Factory
{
    /** @var class-string<RecoveryCode> */
    protected $model = RecoveryCode::class;

    /**
     * Define a valid recovery-code record.
     */
    public function definition(): array
    {
        return [
            'batch_id' => (string) Str::uuid(),
            'subject_type' => 'users',
            'subject_id' => (string) fake()->numberBetween(1, 100000),
            'code_hash' => hash('sha256', fake()->uuid()),
        ];
    }
}

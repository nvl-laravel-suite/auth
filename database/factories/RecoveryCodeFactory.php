<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Nvl\Auth\Models\RecoveryCode;
use Nvl\Auth\Models\User;

/**
 * Builds hashed one-time recovery-code records.
 *
 * @api
 *
 * @extends Factory<RecoveryCode>
 */
final class RecoveryCodeFactory extends Factory
{
    /** @var class-string<RecoveryCode> */
    protected $model = RecoveryCode::class;

    /**
     * Define a valid recovery-code record.
     *
     * @return array<model-property<RecoveryCode>, mixed>
     */
    public function definition(): array
    {
        return [
            'batch_id' => (string) Str::uuid(),
            'subject_type' => 'users',
            'subject_id' => User::factory(),
            'code_hash' => hash('sha256', fake()->uuid()),
        ];
    }

    /** Associate a persisted package principal using Auth's native subject alias.
     *
     * @api
     */
    public function forSubject(User $subject): static
    {
        if (! $subject->exists || $subject->getKey() === null
            || $subject->getConnection() !== (new RecoveryCode)->getConnection()) {
            throw new InvalidArgumentException('Auth subject fixtures require a persisted principal on their connection.');
        }

        return $this->state(['subject_type' => 'users', 'subject_id' => $subject->getKey()]);
    }
}

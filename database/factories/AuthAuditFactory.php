<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\AuthAudit;

/**
 * Builds bounded Auth audit records.
 *
 * @extends Factory<AuthAudit>
 */
final class AuthAuditFactory extends Factory
{
    /** @var class-string<AuthAudit> */
    protected $model = AuthAudit::class;

    /**
     * Define a valid audit fact.
     */
    public function definition(): array
    {
        return [
            'action' => 'authentication.succeeded',
            'outcome' => 'success',
            'request_id' => fake()->uuid(),
            'metadata' => [],
        ];
    }
}

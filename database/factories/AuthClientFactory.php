<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\AuthClient;

/**
 * Builds package-managed first-party clients for tests and seeders.
 *
 * @extends Factory<AuthClient>
 */
final class AuthClientFactory extends Factory
{
    /** @var class-string<AuthClient> */
    protected $model = AuthClient::class;

    /**
     * Define a valid client record.
     */
    public function definition(): array
    {
        return [
            'name' => fake()->company(),
            'surface' => 'web',
            'base_url' => 'https://'.fake()->domainName(),
            'return_paths' => ['/dashboard'],
            'allowed_origins' => [],
            'allowed_flows' => ['login'],
            'metadata' => [],
            'is_active' => true,
        ];
    }
}

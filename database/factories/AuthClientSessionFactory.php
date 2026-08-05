<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\AuthClient;
use Nvl\Auth\Models\AuthClientSession;

/**
 * Builds client-to-Laravel-session correlation records.
 *
 * @extends Factory<AuthClientSession>
 */
final class AuthClientSessionFactory extends Factory
{
    /** @var class-string<AuthClientSession> */
    protected $model = AuthClientSession::class;

    /**
     * Define a valid client-session record.
     */
    public function definition(): array
    {
        return [
            'client_id' => AuthClient::factory(),
            'session_id_hash' => hash('sha256', fake()->uuid()),
            'metadata' => [],
            'last_seen_at' => now(),
        ];
    }
}

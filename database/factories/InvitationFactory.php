<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Models\Invitation;

/**
 * Builds simple invitation records without exposing a bearer token.
 *
 * @extends Factory<Invitation>
 */
final class InvitationFactory extends Factory
{
    /** @var class-string<Invitation> */
    protected $model = Invitation::class;

    /**
     * Define a valid invitation record.
     */
    public function definition(): array
    {
        $recipient = fake()->unique()->safeEmail();

        return [
            'token_hash' => hash('sha256', fake()->uuid()),
            'recipient' => $recipient,
            'recipient_hash' => hash('sha256', $recipient),
            'type' => 'registration',
            'purpose' => 'registration',
            'roles' => [],
            'permissions' => [],
            'metadata' => [],
            'resend_count' => 0,
            'expires_at' => now()->addDay(),
        ];
    }
}

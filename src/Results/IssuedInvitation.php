<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\Models\Invitation;

/**
 * Returns a persisted invitation and its one-time plaintext token.
 */
final readonly class IssuedInvitation
{
    /**
     * Create an invitation issuance result.
     */
    public function __construct(
        public Invitation $invitation,
        public string $token,
    ) {}

    /**
     * Redact the bearer token during inspection.
     *
     * @return array{invitation_id: string, token: string}
     */
    public function __debugInfo(): array
    {
        return ['invitation_id' => $this->invitation->identifier(), 'token' => '[REDACTED]'];
    }
}

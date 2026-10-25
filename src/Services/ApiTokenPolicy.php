<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Enforces the host's API-token ability catalog.
 */
final readonly class ApiTokenPolicy
{
    /**
     * Create the API-token policy.
     */
    public function __construct(private ApiTokenAbilityProvider $abilities, private AuthOwnerAdmission $owners, private AuthOwnershipState $state) {}

    /**
     * Require every requested ability to be allowlisted for the subject.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function authorize(Authenticatable $subject, array $data): void
    {
        $this->authorizeSubject($subject);
        $allowed = $this->abilities->abilities($subject);
        if (in_array('*', $allowed, true)) {
            return;
        }
        foreach ($data['abilities'] as $ability) {
            if (! in_array($ability, $allowed, true)) {
                throw new AuthException('api_token_ability_forbidden', 'An API token ability is not permitted.', 422);
            }
        }
    }

    /** Require a fresh eligible principal in the active owner or explicit central boundary. */
    public function authorizeSubject(Authenticatable $subject): void
    {
        if ($this->state->configured()) {
            $this->owners->assertAllowed($subject);

            return;
        }
    }
}

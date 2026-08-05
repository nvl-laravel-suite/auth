<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\ApiTokenData;

/**
 * Enforces the host's API-token ability catalog.
 */
final readonly class ApiTokenPolicy
{
    /**
     * Create the API-token policy.
     */
    public function __construct(private ApiTokenAbilityProvider $abilities) {}

    /**
     * Require every requested ability to be allowlisted for the subject.
     */
    public function authorize(Authenticatable $subject, ApiTokenData $data): void
    {
        $allowed = $this->abilities->abilities($subject);

        if (in_array('*', $allowed, true)) {
            return;
        }

        foreach ($data->abilities as $ability) {
            if (! in_array($ability, $allowed, true)) {
                throw new AuthException('api_token_ability_forbidden', 'An API token ability is not permitted.', 422);
            }
        }
    }
}

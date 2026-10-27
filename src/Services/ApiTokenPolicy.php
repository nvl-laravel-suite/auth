<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\ApiTokenAbilityProvider;
use Nvl\Auth\Contracts\AuthenticationEligibility;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Auth\CanonicalActorResolver;

/**
 * Enforces the host's API-token ability catalog.
 *
 * @internal
 */
final readonly class ApiTokenPolicy
{
    /**
     * Create the API-token policy.
     */
    public function __construct(private ApiTokenAbilityProvider $abilities, private AuthOwnerAdmission $owners, private AuthOwnershipState $state, private CanonicalActorResolver $actors, private AuthenticationEligibility $eligibility) {}

    /**
     * Require every requested ability to be allowlisted for the subject.
     *
     * @param  array{name: string, abilities: list<string>, expiresAt: CarbonImmutable|null}  $data
     */
    public function authorize(Authenticatable $subject, array $data): Authenticatable
    {
        $subject = $this->authorizeSubject($subject);
        $this->eligibility->assertEligible($subject, AuthenticationPurpose::CredentialLogin);
        $allowed = $this->abilities->abilities($subject);
        if (in_array('*', $allowed, true)) {
            return $subject;
        }
        foreach ($data['abilities'] as $ability) {
            if (! in_array($ability, $allowed, true)) {
                throw new AuthException('api_token_ability_forbidden', 'An API token ability is not permitted.', 422);
            }
        }

        return $subject;
    }

    /** Require a fresh persisted principal in the active owner or explicit central boundary. */
    public function authorizeSubject(Authenticatable $subject): Authenticatable
    {
        try {
            $subject = $this->actors->resolve($subject);
        } catch (AuthorizationException $exception) {
            throw new AuthException('subject_unavailable', 'The authenticated subject is unavailable.', 404, previous: $exception);
        }
        if ($this->state->configured()) {
            $this->owners->assertAllowed($subject);
        }

        return $subject;
    }
}

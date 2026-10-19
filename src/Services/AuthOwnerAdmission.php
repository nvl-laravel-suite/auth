<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Container\Container;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\TransientToken;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\OwnerBoundApiTokenManager;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Ownership\AuthOwnerAccess;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Ownership\Contracts\OwnerAccess;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Support\Ownership\Contracts\OwnershipContext;
use Nvl\Support\Ownership\Contracts\OwnershipReadiness;
use Nvl\Support\Ownership\Exceptions\OwnershipViolation;

/**
 * Revalidates the principal, optional membership, and authoritative native token binding.
 *
 * @api
 */
final readonly class AuthOwnerAdmission
{
    public function __construct(private Container $container, private OwnershipContext $context, private MembershipPrincipalResolver $principals, private ApiTokenManager $tokens, private OwnershipReadiness $readiness, private AuthOwnershipState $state) {}

    public function assertAllowed(Authenticatable $subject): void
    {
        $this->state->configured();
        if ($this->context->snapshot()->publicSite !== null) {
            throw new OwnershipViolation('Public site access cannot grant Auth account or management authority.');
        }
        $owner = $this->context->requireOwner();
        $canonical = $this->container->make(OwnerIdentityResolver::class)->resolve($owner);
        $principal = $this->principals->resolve(SubjectReference::fromAuthenticatable($subject));
        $access = config('nvl-auth.features.memberships.enabled') === true ? AuthOwnerAccess::class : OwnerAccess::class;
        $this->container->make($access)->assertCanEnter($principal, $canonical);
        if (! method_exists($subject, 'currentAccessToken')) {
            return;
        }
        $token = (new \ReflectionMethod($subject, 'currentAccessToken'))->invoke($subject);
        if ($token === null || $token instanceof TransientToken) {
            return;
        }
        $this->readiness->assertActive('auth.tokens');
        $id = $token instanceof Model ? $token->getKey() : null;
        if ((! is_string($id) && ! is_int($id)) || ! $this->tokens instanceof OwnerBoundApiTokenManager
            || $this->tokens->ownerForToken($principal, (string) $id) != $owner) {
            throw new AuthException('owner_token_invalid', 'The access token is unavailable for this owner.', 403);
        }
    }
}

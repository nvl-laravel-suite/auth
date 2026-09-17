<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\TransientToken;
use Nvl\Auth\Contracts\ApiTokenManager;
use Nvl\Auth\Contracts\MembershipPrincipalResolver;
use Nvl\Auth\Contracts\TenantBoundApiTokenManager;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Contracts\TenantMembershipAccess;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Admits a fresh member and, when present, its immutable tenant-bound Sanctum token. */
final readonly class AuthTenantAdmission
{
    public function __construct(
        private MembershipPrincipalResolver $principals,
        private TenantMembershipAccess $memberships,
        private ApiTokenManager $tokens,
    ) {}

    public function assertAllowed(Authenticatable $subject, TenantId $tenant): void
    {
        $principal = $this->principals->resolve(SubjectReference::fromAuthenticatable($subject));
        $this->memberships->assertMember($principal, $tenant);
        if (! method_exists($subject, 'currentAccessToken')) {
            return;
        }

        $token = (new \ReflectionMethod($subject, 'currentAccessToken'))->invoke($subject);
        if ($token === null || $token instanceof TransientToken) {
            return;
        }
        if (! $token instanceof Model || ! $this->tokens instanceof TenantBoundApiTokenManager) {
            throw AuthException::invalidConfiguration(
                'Tenant token admission requires a tenant-bound API token manager.',
            );
        }
        $identifier = $token->getKey();
        $expiresAt = $token->getAttribute('expires_at');
        if ((! is_string($identifier) && ! is_int($identifier))
            || ($expiresAt instanceof DateTimeInterface && $expiresAt->getTimestamp() <= now()->getTimestamp())
            || $this->tokens->tenantForToken($principal, (string) $identifier)?->value !== $tenant->value) {
            throw new AuthException('tenant_token_invalid', 'The access token is unavailable for this tenant.', 403);
        }
    }
}

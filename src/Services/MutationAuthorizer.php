<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\SystemMutationAccess;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\SystemMutationContext;

/**
 * Authorizes either a human management actor or a trusted system context.
 */
final readonly class MutationAuthorizer
{
    /**
     * Create the dual-path mutation authorizer.
     */
    public function __construct(
        private ManagementAuthorizer $management,
        private SystemMutationAccess $systems,
    ) {}

    /**
     * Authorize one mutation and return its optional audit actor.
     */
    public function authorize(
        Authenticatable|SystemMutationContext $authority,
        string $ability,
        mixed $target = null,
    ): ?Authenticatable {
        if ($authority instanceof Authenticatable) {
            $this->management->authorize($authority, $ability, $target);

            return $authority;
        }

        if (! $this->systems->allows($authority, $ability, $target)) {
            throw new AuthException('system_mutation_forbidden', 'This system Auth mutation is not authorized.', 403);
        }

        return $authority->actor;
    }

    /**
     * Return trace metadata when the mutation is system-owned.
     *
     * @return array<string, mixed>
     */
    public function metadata(Authenticatable|SystemMutationContext $authority): array
    {
        return $authority instanceof SystemMutationContext
            ? $authority->auditMetadata()
            : [];
    }
}

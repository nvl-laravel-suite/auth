<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Ownership\Contracts\OwnershipContextParticipant;
use Nvl\Support\Ownership\Enums\OwnershipContextMode;
use Nvl\Support\Ownership\ValueObjects\OwnershipSnapshot;
use Spatie\Permission\PermissionRegistrar;
use Throwable;

/** Installs the complete verified owner identity as the temporary RBAC team. @internal */
final readonly class AuthOwnerContextParticipant implements OwnershipContextParticipant
{
    /** Retain the registrar and weakly tracked principals without retaining an owner. */
    public function __construct(private PermissionRegistrar $registrar, private RbacPrincipalTracker $principals, private AuthOwnershipState $state, private PermissionStorageReadiness $readiness) {}

    /** Install the next team and restore cached principal relations on every exit.
     * @return Closure(): void
     */
    public function enter(OwnershipSnapshot $next): Closure
    {
        if ($this->state->configured()) {
            $this->readiness->assertOwnerTeams();
        }
        $previous = $this->registrar->getPermissionsTeamId();
        $previousCache = $this->registrar->cacheKey;
        try {
            $this->principals->clearRelations();
            $cache = config('permission.cache.key', 'spatie.permission.cache');
            if (! is_string($cache) || $cache === '') {
                throw AuthException::invalidConfiguration('RBAC permission cache requires an explicit namespace.');
            }
            $this->registrar->cacheKey = $cache.'.'.($next->owner?->scopeKey() ?? 'central');
            $this->registrar->forgetCachedPermissions();
            $this->registrar->setPermissionsTeamId($next->owner?->scopeKey() ?? ($next->mode === OwnershipContextMode::Central ? 'central' : null));
        } catch (Throwable $exception) {
            $this->registrar->setPermissionsTeamId($previous);
            $this->registrar->cacheKey = $previousCache;
            $this->registrar->clearPermissionsCollection();
            throw $exception;
        }

        return function () use ($previous, $previousCache): void {
            $this->principals->clearRelations();
            $this->registrar->setPermissionsTeamId($previous);
            $this->registrar->cacheKey = $previousCache;
            $this->registrar->clearPermissionsCollection();
        };
    }
}

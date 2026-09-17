<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Closure;
use Nvl\Tenancy\Contracts\TenantContextParticipant;
use Nvl\Tenancy\Enums\TenantContextMode;
use Nvl\Tenancy\ValueObjects\TenantContextSnapshot;
use Spatie\Permission\PermissionRegistrar;
use Throwable;

/** Installs and restores Spatie's tenant team identifier for each scope. */
final readonly class AuthTenantContextParticipant implements TenantContextParticipant
{
    public function __construct(private PermissionRegistrar $registrar, private RbacPrincipalTracker $principals) {}

    public function enter(TenantContextSnapshot $next): Closure
    {
        $previous = $this->registrar->getPermissionsTeamId();
        try {
            $this->principals->clearRelations();
            $this->registrar->setPermissionsTeamId(
                $next->mode === TenantContextMode::Tenant ? $next->tenantId?->value : null,
            );
        } catch (Throwable $exception) {
            $this->registrar->setPermissionsTeamId($previous);
            throw $exception;
        }

        return function () use ($previous): void {
            $this->principals->clearRelations();
            $this->registrar->setPermissionsTeamId($previous);
        };
    }
}

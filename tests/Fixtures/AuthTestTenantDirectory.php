<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\Exceptions\TenantNotFound;
use Nvl\Tenancy\ValueObjects\TenantDescriptor;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Provides exactly two mutable tenant descriptors for Auth integration tests. */
final class AuthTestTenantDirectory implements TenantDirectory
{
    /** @var array<string, TenantStatus> */
    private array $statuses = [
        AuthTenancyScenario::A => TenantStatus::Active,
        AuthTenancyScenario::B => TenantStatus::Active,
    ];

    /** Resolve one known test tenant. */
    public function find(TenantId $tenant): TenantDescriptor
    {
        $status = $this->statuses[$tenant->value] ?? null;
        if (! $status instanceof TenantStatus) {
            throw new TenantNotFound;
        }

        return new TenantDescriptor($tenant, $status);
    }

    /** Change only the in-memory lifecycle state of one known tenant. */
    public function setStatus(TenantId $tenant, TenantStatus $status): void
    {
        $this->find($tenant);
        $this->statuses[$tenant->value] = $status;
    }
}

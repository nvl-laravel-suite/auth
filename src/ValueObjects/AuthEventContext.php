<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;
use Nvl\Support\Tenancy\Contracts\TenantContext;
use Nvl\Support\Tenancy\Enums\TenantContextMode;
use Nvl\Support\Tenancy\ValueObjects\TenantContextSnapshot;
use Nvl\Support\Tenancy\ValueObjects\TenantId;
use Nvl\Support\Tenancy\ValueObjects\TenantJobEnvelope;

/** Captures immutable Auth event ownership before context can change. */
final readonly class AuthEventContext
{
    public function __construct(
        public TenantContextMode $mode,
        public ?TenantId $tenantId = null,
    ) {
        if (($this->mode === TenantContextMode::Tenant) !== ($this->tenantId instanceof TenantId)) {
            throw new InvalidArgumentException('Only tenant Auth event context may carry a tenant identifier.');
        }
    }

    public static function capture(TenantContext $context): self
    {
        $snapshot = $context->snapshot();

        return new self($snapshot->mode, $snapshot->tenantId);
    }

    public static function platform(): self
    {
        return new self(TenantContextMode::Platform);
    }

    public function envelope(): TenantJobEnvelope
    {
        return new TenantJobEnvelope(new TenantContextSnapshot($this->mode, $this->tenantId));
    }
}

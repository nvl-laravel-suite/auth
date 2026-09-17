<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Nvl\Auth\Models\Invitation;
use Nvl\Tenancy\Contracts\TenantDirectory;
use Nvl\Tenancy\Enums\TenantStatus;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Performs the one bounded secret lookup allowed before entering invitation tenancy. */
final readonly class InvitationTenantBootstrap
{
    public function __construct(private SecretHasher $hasher, private TenantDirectory $directory) {}

    public function tenantForToken(string $token): ?TenantId
    {
        if (config('tenancy.enabled') !== true) {
            return null;
        }

        /** @var Invitation|null $invitation */
        $invitation = Invitation::query()
            ->where('token_hash', $this->hasher->hash('invitation-token', $token))
            ->first();
        if (! $invitation instanceof Invitation || ! $invitation->isUsable() || ! is_string($invitation->tenant_id)) {
            return null;
        }

        $tenant = new TenantId($invitation->tenant_id);
        $descriptor = $this->directory->find($tenant);

        return $descriptor->id->value === $tenant->value && $descriptor->status === TenantStatus::Active
            ? $tenant
            : null;
    }
}

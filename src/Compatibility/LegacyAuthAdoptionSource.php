<?php

declare(strict_types=1);

namespace Nvl\Auth\Compatibility;

use Illuminate\Database\Eloquent\Model;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;

/** Names the three fixed historical Auth sources without accepting arbitrary table metadata. @internal */
final readonly class LegacyAuthAdoptionSource
{
    /** Retain effective canonical native resource definitions. */
    public function __construct(private OwnershipResourceRegistry $resources) {}

    /** Preserve the original physical transaction and key of each historical workflow. */
    public function sourceFor(string $resource): Model
    {
        $target = new ($this->resources->get($resource)->model);
        $source = match ($resource) {
            'auth.memberships' => new TenantMembership,
            'auth.membership_locks' => new TenantMembershipLock,
            'auth.authentication_intents' => new TenantAuthenticationIntent,
            default => $target,
        };
        if ($source->getConnection() !== $target->getConnection()) {
            throw new OwnershipConfigurationInvalid('Historical Auth staging requires the same actual source connection.');
        }

        return $source->getConnection()->getSchemaBuilder()->hasTable($source->getTable()) ? $source : $target;
    }
}

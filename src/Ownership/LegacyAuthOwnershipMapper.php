<?php

declare(strict_types=1);

namespace Nvl\Auth\Ownership;

use Generator;
use Nvl\Auth\Models\TenantAuthenticationIntent;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\ValueObjects\OwnershipMapping;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;
use Nvl\Support\Ownership\Services\OwnershipResourceRegistry;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Inventories immutable legacy identities without writing storage or guessing native owners.
 *
 * @api
 */
final readonly class LegacyAuthOwnershipMapper
{
    /** Retain the effective graph and canonical native owner resolver. */
    public function __construct(private OwnershipResourceRegistry $resources, private OwnerIdentityResolver $owners) {}

    /**
     * Describe every historical record, including revoked memberships and consumed intents.
     *
     * @param  array<string, OwnerReference>  $legacyOwners
     * @return Generator<int, OwnershipMapping>
     */
    public function mappings(array $legacyOwners): Generator
    {
        $seen = [];
        foreach ($legacyOwners as $tenant => $owner) {
            if ($tenant === '' || isset($seen[$owner->scopeKey()])) {
                throw new OwnershipConfigurationInvalid('Legacy owner mappings must be explicit and cannot silently merge native owners.');
            }
            $this->owners->resolve($owner);
            $seen[$owner->scopeKey()] = true;
        }
        foreach ($this->resources->all() as $key => $definition) {
            if ($definition->family !== 'auth' || $definition->ownership->strategy === 'unscoped') {
                continue;
            }
            $target = new $definition->model;
            $source = match ($key) {
                'auth.memberships' => new TenantMembership,
                'auth.membership_locks' => new TenantMembershipLock,
                'auth.authentication_intents' => new TenantAuthenticationIntent,
                default => $target,
            };
            $connection = $source->getConnection();
            if ($connection !== $target->getConnection()) {
                throw new OwnershipConfigurationInvalid('Legacy Auth staging must preserve the actual source transaction.');
            }
            if (! $connection->getSchemaBuilder()->hasTable($source->getTable())) {
                continue;
            }
            foreach ($connection->table($source->getTable())->useWritePdo()->orderBy($source->getKeyName())->cursor() as $row) {
                $id = $row->{$source->getKeyName()};
                $tenant = $row->tenant_id ?? null;
                if (! is_string($id) || ($tenant !== null && ! is_string($tenant))) {
                    throw new OwnershipConfigurationInvalid('Historical Auth identities require their original persisted scalar keys.');
                }
                $owner = $tenant === null ? null : ($legacyOwners[$tenant] ?? throw new OwnershipConfigurationInvalid('A historical Auth tenant has no reviewed native owner.'));
                if ($owner === null && ! $definition->allowsCentral) {
                    throw new OwnershipConfigurationInvalid('This Auth resource requires an explicit native owner mapping.');
                }
                if (isset($row->owner_scope_key) && $row->owner_scope_key !== ($owner?->scopeKey() ?? 'central')) {
                    throw new OwnershipConfigurationInvalid('A legacy mapping cannot relabel a previously partitioned Auth record.');
                }
                yield new OwnershipMapping($key, $id, $owner, ['legacy_source_table' => $source->getTable(), 'legacy_source_key' => $source->getKeyName()], $tenant);
            }
        }
    }
}

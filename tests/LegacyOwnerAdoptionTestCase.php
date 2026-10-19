<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests;

use Illuminate\Support\Facades\DB;
use Nvl\Auth\Ownership\LegacyAuthOwnershipMapper;
use Nvl\Ownership\Services\OwnerIdentityResolver;
use Nvl\Ownership\Tests\Fixtures\Company;
use Nvl\Ownership\ValueObjects\OwnershipMapping;

/** Rehearses actual historical Auth records before native target tables exist. */
abstract class LegacyOwnerAdoptionTestCase extends OwnerScopeTestCase
{
    public const string Tenant = '81f5650f-713a-43c3-a34b-a7326a1c2804';

    public const string Membership = '81f5650f-713a-43c3-a34b-a7326a1c2805';

    public const string Intent = '81f5650f-713a-43c3-a34b-a7326a1c2806';

    /** Preserve reviewed historical identities, status, revision and consumed proof bytes.
     * @return list<OwnershipMapping>
     */
    protected function adoptionMappings(): array
    {
        (require __DIR__.'/../database/migrations/tenancy/2026_09_16_000000_nvl_auth_prepare_auth_tenancy.php')->up();
        DB::table('nvl_auth_tenant_memberships')->insert(['id' => self::Membership, 'tenant_id' => self::Tenant, 'subject_type' => 'actor', 'subject_id' => '1', 'status' => 'suspended', 'is_owner' => true, 'revision' => 4294967301, 'created_at' => '2026-01-01 00:00:00', 'updated_at' => '2026-01-02 00:00:00']);
        DB::table('nvl_auth_tenant_membership_locks')->insert(['tenant_id' => self::Tenant]);
        DB::table('nvl_auth_tenant_authentication_intents')->insert(['id' => self::Intent, 'tenant_id' => self::Tenant, 'purpose' => 'login', 'nonce_hash' => str_repeat('a', 64), 'session_binding_hash' => str_repeat('b', 64), 'subject_type' => 'actor', 'subject_id' => '1', 'expires_at' => '2026-01-01 00:00:00', 'consumed_at' => '2026-01-01 00:00:00']);
        $owner = app(OwnerIdentityResolver::class)->reference(Company::findOrFail(7));

        return iterator_to_array(app(LegacyAuthOwnershipMapper::class)->mappings([self::Tenant => $owner]));
    }
}

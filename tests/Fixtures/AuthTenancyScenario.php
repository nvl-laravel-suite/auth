<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Closure;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\TenantMembershipLock;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Tenancy\Services\TenantRunner;
use Nvl\Tenancy\ValueObjects\PlatformOperation;
use Nvl\Tenancy\ValueObjects\TenantId;

/** Creates explicit tenancy arrangements without replacing production mutations. */
final class AuthTenancyScenario
{
    public const string A = '018f0000-0000-7000-8000-000000000001';

    public const string B = '018f0000-0000-7000-8000-000000000002';

    public function a(): TenantId
    {
        return new TenantId(self::A);
    }

    public function b(): TenantId
    {
        return new TenantId(self::B);
    }

    public function run(TenantId $tenant, Closure $operation): mixed
    {
        return app(TenantRunner::class)->run($tenant, $operation);
    }

    public function platform(Closure $operation): mixed
    {
        return app(TenantRunner::class)->platform(
            new PlatformOperation('auth-test.setup', 'system', 'fixture'),
            $operation,
        );
    }

    public function member(TenantId $tenant, SubjectReference $subject, bool $owner = false): TenantMembership
    {
        TenantMembershipLock::query()->firstOrCreate(['tenant_id' => $tenant->value]);

        return TenantMembership::factory()->create([
            'tenant_id' => $tenant->value,
            'subject_type' => $subject->type,
            'subject_id' => $subject->identifier,
            'status' => MembershipStatus::Active,
            'is_owner' => $owner,
            'revision' => 1,
        ]);
    }
}

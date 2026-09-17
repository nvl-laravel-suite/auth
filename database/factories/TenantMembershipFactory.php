<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;

/** @extends Factory<TenantMembership> */
final class TenantMembershipFactory extends Factory
{
    /** @var class-string<TenantMembership> */
    protected $model = TenantMembership::class;

    /** @return array<string, mixed> */
    public function definition(): array
    {
        return [
            'tenant_id' => fake()->uuid(),
            'subject_type' => 'fixture',
            'subject_id' => fake()->uuid(),
            'status' => MembershipStatus::Active,
            'is_owner' => false,
            'revision' => 1,
        ];
    }
}

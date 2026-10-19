<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\OwnerMembership;
use Nvl\Auth\Models\User;
use Nvl\Support\Models\ConfiguredModelResolver;
use Nvl\Support\Ownership\Exceptions\OwnershipConfigurationInvalid;

/** Creates native owner fixtures only inside an already admitted owner.
 * @extends Factory<OwnerMembership>
 *
 * @api
 */
final class OwnerMembershipFactory extends Factory
{
    /** @var class-string<OwnerMembership> */
    protected $model = OwnerMembership::class;

    /** Resolve the exact configured native model for inherited consumer factories.
     * @return class-string<OwnerMembership>
     */
    public function modelName(): string
    {
        $configured = config('nvl-auth.features.memberships.models.membership', OwnerMembership::class);
        if (! is_string($configured)) {
            throw new OwnershipConfigurationInvalid('Native membership factories require a configured model class.');
        }

        return (new ConfiguredModelResolver)->resolve($configured, OwnerMembership::class);
    }

    /** @return array<model-property<OwnerMembership>, mixed> */
    public function definition(): array
    {
        return ['subject_type' => User::class, 'subject_id' => User::factory(), 'status' => MembershipStatus::Active, 'is_owner' => false, 'revision' => 1];
    }
}

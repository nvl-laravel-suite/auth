<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Factories\Factory;
use InvalidArgumentException;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Auth\Models\TenantMembership;
use Nvl\Auth\Models\User;
use Nvl\Support\Tenancy\Contracts\TenantContext;
use Nvl\Support\Tenancy\Contracts\TenantDirectory;
use Nvl\Support\Tenancy\Enums\TenantStatus;
use Nvl\Support\Tenancy\ValueObjects\TenantId;

/** @api
 * @extends Factory<TenantMembership> */
final class TenantMembershipFactory extends Factory
{
    /** @var class-string<TenantMembership> */
    protected $model = TenantMembership::class;

    /** Guard explicit membership inputs after native parent expansion.
     *
     * @internal
     */
    public function configure(): static
    {
        $expandRelationships = true;

        return $this->state(function () use (&$expandRelationships): array {
            $expandRelationships = $this->expandRelationships;

            return [];
        })->afterMaking(function (TenantMembership $membership) use (&$expandRelationships): void {
            if (! $expandRelationships) {
                return;
            }
            $tenantId = $membership->getAttribute('tenant_id');
            if (! is_string($tenantId)) {
                throw new InvalidArgumentException('Membership fixtures require an explicit active directory tenant.');
            }
            $tenant = new TenantId($tenantId);
            if (Container::getInstance()->make(TenantDirectory::class)->find($tenant)->status !== TenantStatus::Active) {
                throw new InvalidArgumentException('Membership fixtures require an active directory tenant.');
            }
            if (config('nvl-tenancy.enabled') === true
                && Container::getInstance()->make(TenantContext::class)->requireTenant()->value !== $tenant->value) {
                throw new InvalidArgumentException('Membership fixture tenancy differs from the admitted context.');
            }
            if ($membership->subject_type === 'users') {
                $subject = User::query()->findOrFail($membership->subject_id);
                if ($subject->getConnection() !== $membership->getConnection()) {
                    throw new InvalidArgumentException('Membership principals require the fixture connection.');
                }
            }
        });
    }

    /** Define native package fixture attributes.
     *
     * @return array<model-property<TenantMembership>, mixed>
     */
    public function definition(): array
    {
        return [
            'tenant_id' => null,
            'subject_type' => 'users',
            'subject_id' => User::factory(),
            'status' => MembershipStatus::Active,
            'is_owner' => false,
            'revision' => 1,
        ];
    }

    /** Associate a real active tenant without adopting or entering its context.
     *
     * @api
     */
    public function forTenant(TenantId $tenant): static
    {
        $directory = Container::getInstance()->make(TenantDirectory::class);
        if ($directory->find($tenant)->status !== TenantStatus::Active) {
            throw new InvalidArgumentException('Membership fixtures require an active tenant.');
        }
        if (config('nvl-tenancy.enabled') === true
            && Container::getInstance()->make(TenantContext::class)->requireTenant()->value !== $tenant->value) {
            throw new InvalidArgumentException('Membership fixtures require the explicitly admitted tenant.');
        }

        return $this->state(['tenant_id' => $tenant->value]);
    }

    /** Associate a persisted native package principal.
     *
     * @api
     */
    public function forSubject(User $subject): static
    {
        if (! $subject->exists || $subject->getKey() === null
            || $subject->getConnection() !== (new TenantMembership)->getConnection()) {
            throw new InvalidArgumentException('Membership fixtures require a persisted principal on their connection.');
        }

        return $this->state(['subject_type' => 'users', 'subject_id' => $subject->getKey()]);
    }
}

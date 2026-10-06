<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Config;
use Nvl\Auth\Models\Permission;

/** @api
 * @extends Factory<Permission> */
final class PermissionFactory extends Factory
{
    /** @var class-string<Permission> */
    protected $model = Permission::class;

    /** Define native package fixture attributes.
     *
     * @return array<model-property<Permission>, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => 'permission.'.fake()->unique()->slug(2),
            'guard_name' => Config::string('nvl-auth.features.rbac.settings.guard', 'web'),
            'display_name' => fake()->words(2, true),
            'is_system' => false,
        ];
    }
}

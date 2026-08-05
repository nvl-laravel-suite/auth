<?php

declare(strict_types=1);

namespace Nvl\Auth\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Config;
use Nvl\Auth\Models\Role;

/** @extends Factory<Role> */
final class RoleFactory extends Factory
{
    /** @var class-string<Role> */
    protected $model = Role::class;

    public function definition(): array
    {
        return [
            'name' => 'role-'.fake()->unique()->slug(2),
            'guard_name' => Config::string('nvl-auth.features.rbac.settings.guard', 'web'),
            'display_name' => fake()->words(2, true),
            'priority' => 0,
            'is_system' => false,
        ];
    }
}

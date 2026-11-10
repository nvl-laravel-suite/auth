<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Nvl\Auth\Definitions\Tables\AuthTables;

/**
 * Validated replacement mutation for one principal's roles.
 *
 * @api
 */
final class SyncUserRolesData
{
    /**
     * @param  list<string>  $roles
     */
    public function __construct(public readonly array $roles)
    {
        if (count($this->roles) > 100 || count(array_unique($this->roles)) !== count($this->roles)) {
            throw new InvalidArgumentException('User roles must be a distinct list containing at most 100 names.');
        }

        foreach ($this->roles as $role) {
            if (trim($role) === '' || mb_strlen($role) > 160) {
                throw new InvalidArgumentException('User role names must contain between one and 160 characters.');
            }
        }
    }

    /**
     * Return role assignment validation rules.
     *
     * @return array<string, list<mixed>>
     */
    public static function rules(): array
    {
        $roles = Config::string('nvl-auth.tables.roles', AuthTables::get(AuthTables::Roles));

        return [
            'roles' => ['required', 'array', 'max:100'],
            'roles.*' => ['string', 'distinct', "exists:{$roles},name"],
        ];
    }
}

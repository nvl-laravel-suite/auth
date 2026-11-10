<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Nvl\Auth\Definitions\Tables\AuthTables;

/**
 * Validated replacement mutation for one principal's direct permissions.
 *
 * @api
 */
final class SyncUserPermissionsData
{
    /**
     * @param  list<string>  $permissions
     */
    public function __construct(public readonly array $permissions)
    {
        if (count($this->permissions) > 250 || count(array_unique($this->permissions)) !== count($this->permissions)) {
            throw new InvalidArgumentException('User permissions must be a distinct list containing at most 250 names.');
        }

        foreach ($this->permissions as $permission) {
            if (trim($permission) === '' || mb_strlen($permission) > 160) {
                throw new InvalidArgumentException('User permission names must contain between one and 160 characters.');
            }
        }
    }

    /**
     * Return direct permission assignment validation rules.
     *
     * @return array<string, list<mixed>>
     */
    public static function rules(): array
    {
        $permissions = Config::string('nvl-auth.tables.permissions', AuthTables::get(AuthTables::Permissions));

        return [
            'permissions' => ['required', 'array', 'max:250'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
        ];
    }
}

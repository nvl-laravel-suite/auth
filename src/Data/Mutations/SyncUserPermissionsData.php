<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated replacement mutation for one principal's direct permissions. */
final class SyncUserPermissionsData extends Data
{
    use DataTransform;

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
        $permissions = Config::string('nvl-auth.tables.permissions', 'nvl_auth_permissions');

        return [
            'permissions' => ['required', 'array', 'max:250'],
            'permissions.*' => ['string', 'distinct', "exists:{$permissions},name"],
        ];
    }
}

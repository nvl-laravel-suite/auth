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
/** Validated replacement mutation for one principal's roles. */
final class SyncUserRolesData extends Data
{
    use DataTransform;

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
        $roles = Config::string('nvl-auth.tables.roles', 'nvl_auth_roles');

        return [
            'roles' => ['required', 'array', 'max:100'],
            'roles.*' => ['string', 'distinct', "exists:{$roles},name"],
        ];
    }
}

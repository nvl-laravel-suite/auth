<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

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
/** Validated request to apply one template to a bounded target role name. */
final class ApplyRoleTemplateData extends Data
{
    use DataTransform;

    /**
     * Create a role-template application mutation.
     */
    public function __construct(
        public readonly string $template,
        public readonly ?string $roleName = null,
    ) {
        if (trim($this->template) === '' || mb_strlen($this->template) > 160) {
            throw new InvalidArgumentException('Role template keys must contain between one and 160 characters.');
        }

        if ($this->roleName !== null && (trim($this->roleName) === '' || mb_strlen($this->roleName) > 160)) {
            throw new InvalidArgumentException('Target role names must contain between one and 160 characters.');
        }
    }

    /**
     * Return role-template application validation rules.
     *
     * @return array<string, list<string>>
     */
    public static function rules(): array
    {
        return [
            'template' => ['required', 'string', 'max:160'],
            'roleName' => ['nullable', 'string', 'max:160'],
        ];
    }
}

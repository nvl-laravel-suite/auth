<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use InvalidArgumentException;

/**
 * Validated request to apply one template to a bounded target role name.
 *
 * @api
 */
final class ApplyRoleTemplateData
{
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

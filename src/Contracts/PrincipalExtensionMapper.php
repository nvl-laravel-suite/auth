<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Models\User;

/**
 * Validates host logical fields and returns fillable physical principal columns.
 *
 * Mapping runs inside the native transaction. It must not persist records, issue
 * credentials, change ownership or perform external effects. Use a consumer
 * Action composing native services for related domain records.
 *
 * @api
 */
interface PrincipalExtensionMapper
{
    /**
     * Preserve omitted fields and explicit nullable values.
     *
     * @param  array<string, mixed>  $extensions
     * @return array<string, mixed>
     */
    public function validateAndMap(PrincipalMutation $mutation, #[\SensitiveParameter] array $extensions, ?User $principal = null): array;
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use InvalidArgumentException;
use Nvl\Auth\Contracts\PrincipalExtensionMapper;
use Nvl\Auth\Enums\PrincipalMutation;
use Nvl\Auth\Models\User;

/**
 * Rejects host fields unless a consumer explicitly supplies their schema.
 *
 * @internal
 */
final readonly class RejectPrincipalExtensions implements PrincipalExtensionMapper
{
    public function validateAndMap(PrincipalMutation $mutation, #[\SensitiveParameter] array $extensions, ?User $principal = null): array
    {
        if ($extensions !== []) {
            throw new InvalidArgumentException('Principal extensions require a configured mapper.');
        }

        return [];
    }
}

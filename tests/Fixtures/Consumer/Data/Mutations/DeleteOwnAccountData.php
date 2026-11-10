<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

/**
 * Validated self-service account deletion confirmation.
 *
 * @api
 */
final class DeleteOwnAccountData
{
    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\RequestPasswordResetData;

/**
 * Defines the request password reset use-case boundary.
 *
 * @api
 */
interface RequestPasswordResetContract
{
    /**
     * Request a reset without revealing whether the identifier exists.
     */
    public function execute(RequestPasswordResetData $data, ?string $locale = null): void;
}

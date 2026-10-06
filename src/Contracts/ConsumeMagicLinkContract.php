<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Nvl\Auth\Data\Mutations\ConsumeMagicLinkData;
use Nvl\Auth\Models\Challenge;

/**
 * Defines the consume magic link use-case boundary.
 *
 * @api
 */
interface ConsumeMagicLinkContract
{
    /**
     * Consume a matching magic link.
     */
    public function execute(ConsumeMagicLinkData $data, string $purpose = 'login'): Challenge;
}

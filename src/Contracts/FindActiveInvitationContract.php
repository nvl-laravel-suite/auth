<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Display\InvitationReadData;
use Nvl\Auth\ValueObjects\InvitationIssuanceContext;

/**
 * Defines the find active invitation use-case boundary.
 *
 * @api
 */
interface FindActiveInvitationContract
{
    /**
     * Find the newest active invitation matching normalized trusted input.
     *
     * @param  list<string>|null  $types
     */
    public function execute(
        string $recipient,
        string $purpose,
        ?array $types = null,
        ?string $context = null,
        ?Authenticatable $actor = null,
        ?InvitationIssuanceContext $issuance = null,
    ): ?InvitationReadData;
}

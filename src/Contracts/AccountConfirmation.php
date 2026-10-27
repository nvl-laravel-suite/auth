<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;

/**
 * Additional host policy after mandatory native recent-grant validation.
 *
 * @api
 */
interface AccountConfirmation
{
    public function assertConfirmed(Authenticatable $subject, AuthenticationEvidence $evidence, RecentAuthenticationPurpose $purpose): void;
}

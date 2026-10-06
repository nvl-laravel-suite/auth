<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;

/**
 * Defines the begin passkey registration use-case boundary.
 *
 * @api
 */
interface BeginPasskeyRegistrationContract
{
    /**
     * Begin registration for an authenticated host subject.
     */
    public function execute(Authenticatable $subject): PasskeyCeremonyOptions;
}

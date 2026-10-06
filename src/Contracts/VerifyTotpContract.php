<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\VerifyTotpData;
use Nvl\Auth\Models\TotpCredential;
use SensitiveParameter;

/**
 * Defines the verify totp use-case boundary.
 *
 * @api
 */
interface VerifyTotpContract
{
    /**
     * Verify one active credential belonging to the subject.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] VerifyTotpData $data,
    ): TotpCredential;
}

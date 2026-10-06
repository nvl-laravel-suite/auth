<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Data\Mutations\ConsumeRecoveryCodeData;
use Nvl\Auth\Models\RecoveryCode;
use SensitiveParameter;

/**
 * Defines the consume recovery code use-case boundary.
 *
 * @api
 */
interface ConsumeRecoveryCodeContract
{
    /**
     * Consume one code belonging to a subject.
     */
    public function execute(
        Authenticatable $subject,
        #[SensitiveParameter] ConsumeRecoveryCodeData $data,
    ): RecoveryCode;
}

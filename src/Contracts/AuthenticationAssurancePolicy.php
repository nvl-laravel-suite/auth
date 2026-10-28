<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthenticationPurpose;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;

/**
 * Additional host assurance requirements after mandatory native enrollment checks.
 *
 * @api
 */
interface AuthenticationAssurancePolicy
{
    public function assertSatisfied(Authenticatable $subject, AuthenticationEvidence $evidence, AuthenticationPurpose $purpose): void;
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Enums\AuthenticationPurpose;

/**
 * Enforces host-replaceable subject eligibility before sensitive authentication operations.
 */
interface AuthenticationEligibility
{
    /**
     * Require the subject to be eligible for the requested authentication purpose.
     */
    public function assertEligible(Authenticatable $subject, AuthenticationPurpose $purpose): void;
}

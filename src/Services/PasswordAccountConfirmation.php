<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\Contracts\AccountConfirmation;
use Nvl\Auth\Enums\RecentAuthenticationPurpose;
use Nvl\Auth\ValueObjects\AuthenticationEvidence;

/**
 * Default policy accepts the already-validated native confirmation evidence.
 *
 * @internal
 */
final readonly class PasswordAccountConfirmation implements AccountConfirmation
{
    public function assertConfirmed(Authenticatable $subject, AuthenticationEvidence $evidence, RecentAuthenticationPurpose $purpose): void {}
}

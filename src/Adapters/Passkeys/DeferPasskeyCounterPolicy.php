<?php

declare(strict_types=1);

namespace Nvl\Auth\Adapters\Passkeys;

use Webauthn\Counter\CounterChecker;
use Webauthn\CredentialRecord;

/**
 * Defers signature-counter policy to the package's locked authentication Action.
 */
final class DeferPasskeyCounterPolicy implements CounterChecker
{
    /**
     * Let cryptographic verification finish before atomic package counter policy.
     */
    public function check(CredentialRecord $credentialRecord, int $currentCounter): void {}
}

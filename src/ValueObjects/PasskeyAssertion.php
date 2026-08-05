<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries verified WebAuthn assertion signals from a ceremony adapter.
 */
final readonly class PasskeyAssertion
{
    /**
     * Create a verified assertion result.
     */
    public function __construct(
        public string $credentialId,
        public int $signatureCounter,
        public bool $backupEligible,
        public bool $backedUp,
        public bool $userVerified,
    ) {
        if (trim($this->credentialId) === ''
            || strlen($this->credentialId) > 4_096
            || $this->signatureCounter < 0) {
            throw new InvalidArgumentException('Passkey assertion identity and counter are invalid.');
        }

        if ($this->backedUp && ! $this->backupEligible) {
            throw new InvalidArgumentException('A backed-up passkey assertion must be backup eligible.');
        }
    }
}

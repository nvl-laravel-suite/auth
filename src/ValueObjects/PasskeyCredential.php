<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries stored passkey material into a stateless ceremony verifier.
 */
final readonly class PasskeyCredential
{
    /**
     * Create one passkey verification credential.
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public string $userHandle,
        public int $signatureCounter,
        public bool $backupEligible,
        public bool $backedUp,
    ) {
        if (trim($this->credentialId) === ''
            || strlen($this->credentialId) > 4_096
            || trim($this->publicKey) === ''
            || strlen($this->publicKey) > 131_072
            || trim($this->userHandle) === ''
            || strlen($this->userHandle) > 1_024
            || $this->signatureCounter < 0) {
            throw new InvalidArgumentException('Stored passkey credential material is invalid.');
        }

        if ($this->backedUp && ! $this->backupEligible) {
            throw new InvalidArgumentException('A backed-up passkey credential must be backup eligible.');
        }
    }
}

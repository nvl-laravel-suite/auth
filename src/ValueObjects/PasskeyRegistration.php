<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries verified WebAuthn registration material from a ceremony adapter.
 */
final readonly class PasskeyRegistration
{
    /**
     * Create verified passkey material.
     *
     * @param  list<string>  $transports
     */
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public string $userHandle,
        public int $signatureCounter,
        public array $transports = [],
        public bool $backupEligible = false,
        public bool $backedUp = false,
    ) {
        if (trim($this->credentialId) === ''
            || strlen($this->credentialId) > 4_096
            || trim($this->publicKey) === ''
            || strlen($this->publicKey) > 131_072
            || trim($this->userHandle) === ''
            || strlen($this->userHandle) > 1_024
            || $this->signatureCounter < 0) {
            throw new InvalidArgumentException('Passkey registration material is invalid.');
        }

        foreach ($this->transports as $transport) {
            if (! self::validTransport($transport)) {
                throw new InvalidArgumentException('Passkey transports must be non-empty strings.');
            }
        }

        if (count($this->transports) > 16 || count(array_unique($this->transports)) !== count($this->transports)) {
            throw new InvalidArgumentException('Passkey transports must be unique and contain at most 16 entries.');
        }

        if ($this->backedUp && ! $this->backupEligible) {
            throw new InvalidArgumentException('A backed-up passkey registration must be backup eligible.');
        }
    }

    /**
     * Determine whether an untrusted authenticator transport is valid.
     */
    private static function validTransport(mixed $transport): bool
    {
        return is_string($transport) && trim($transport) !== '' && mb_strlen($transport) <= 32;
    }
}

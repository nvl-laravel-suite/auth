<?php

declare(strict_types=1);

namespace Nvl\Auth\Results;

use Nvl\Auth\Models\TotpCredential;

/**
 * Returns a pending TOTP credential and one-time provisioning material.
 */
final readonly class TotpEnrollment
{
    /**
     * Create a TOTP enrollment result.
     */
    public function __construct(
        public TotpCredential $credential,
        public string $secret,
        public string $provisioningUri,
    ) {}

    /**
     * Redact enrollment secrets during inspection.
     *
     * @return array{credential_id: string, secret: string, provisioning_uri: string}
     */
    public function __debugInfo(): array
    {
        return [
            'credential_id' => $this->credential->identifier(),
            'secret' => '[REDACTED]',
            'provisioning_uri' => '[REDACTED]',
        ];
    }
}

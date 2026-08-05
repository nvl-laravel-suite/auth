<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use Carbon\CarbonImmutable;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\Models\TotpCredential;
use PragmaRX\Google2FA\Google2FA;
use SensitiveParameter;

/**
 * Generates interoperable TOTP material and rejects replayed timesteps.
 */
final readonly class TotpEngine
{
    /**
     * Create the Google2FA integration.
     */
    public function __construct(
        private Google2FA $google2fa,
        private AuthConfiguration $configuration,
    ) {}

    /**
     * Generate a configured Base32 TOTP secret.
     */
    public function generateSecret(): string
    {
        return $this->configured()->generateSecretKey(
            $this->configuration->integerBetween('features.totp.settings.secret_length', 32, 16, 128),
        );
    }

    /**
     * Build the standard otpauth provisioning URI.
     */
    public function provisioningUri(string $accountName, #[SensitiveParameter] string $secret): string
    {
        return $this->configured()->getQRCodeUrl(
            $this->configuration->string('features.totp.settings.issuer', 'Laravel'),
            trim($accountName),
            $secret,
        );
    }

    /**
     * Resolve an accepted timestep newer than the replay cursor.
     */
    public function acceptedTimestep(
        TotpCredential $credential,
        #[SensitiveParameter] string $code,
    ): ?int {
        $normalized = preg_replace('/[\s-]+/u', '', $code);

        if (! is_string($normalized)
            || strlen($normalized) !== $credential->digits
            || ! ctype_digit($normalized)) {
            return null;
        }

        $google2fa = $this->configured(
            $credential->algorithm,
            $credential->digits,
            $credential->period,
            $credential->allowed_drift,
        );
        $currentTimestep = intdiv(CarbonImmutable::now()->getTimestamp(), $credential->period);
        $accepted = $google2fa->verifyKeyNewer(
            $credential->secret,
            $normalized,
            $credential->last_accepted_timestep ?? -1,
            $credential->allowed_drift,
            $currentTimestep,
        );

        return is_int($accepted) ? $accepted : null;
    }

    /**
     * Return the current configured credential parameters.
     *
     * @return array{algorithm: string, digits: int, period: int, allowed_drift: int}
     */
    public function parameters(): array
    {
        $window = $this->configuration->get('features.totp.settings.window', 1);

        if (! is_int($window) || $window < 0 || $window > 10) {
            throw AuthException::invalidConfiguration('TOTP window must be an integer between zero and ten.');
        }

        $algorithm = mb_strtolower($this->configuration->string('features.totp.settings.algorithm', 'sha1'));

        if (! in_array($algorithm, ['sha1', 'sha256', 'sha512'], true)) {
            throw AuthException::invalidConfiguration('TOTP algorithm must be sha1, sha256, or sha512.');
        }

        $digits = $this->configuration->integerBetween('features.totp.settings.digits', 6, 6, 8);

        if (! in_array($digits, [6, 8], true)) {
            throw AuthException::invalidConfiguration('TOTP digits must be six or eight.');
        }

        return [
            'algorithm' => $algorithm,
            'digits' => $digits,
            'period' => $this->configuration->integerBetween('features.totp.settings.period_seconds', 30, 15, 300),
            'allowed_drift' => $window,
        ];
    }

    /**
     * Configure an isolated Google2FA instance.
     */
    private function configured(
        ?string $algorithm = null,
        ?int $digits = null,
        ?int $period = null,
        ?int $window = null,
    ): Google2FA {
        $parameters = $this->parameters();
        $google2fa = clone $this->google2fa;
        $google2fa->setEnforceGoogleAuthenticatorCompatibility(false);
        $google2fa->setAlgorithm($algorithm ?? $parameters['algorithm']);
        $google2fa->setOneTimePasswordLength($digits ?? $parameters['digits']);
        $google2fa->setKeyRegeneration($period ?? $parameters['period']);
        $google2fa->setWindow($window ?? $parameters['allowed_drift']);

        return $google2fa;
    }
}

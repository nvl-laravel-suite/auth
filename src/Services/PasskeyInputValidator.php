<?php

declare(strict_types=1);

namespace Nvl\Auth\Services;

use JsonException;
use Nvl\Auth\Exceptions\AuthException;

/**
 * Bounds untrusted browser input before invoking a WebAuthn ceremony adapter.
 */
final class PasskeyInputValidator
{
    /**
     * Validate one ceremony identifier and browser response payload.
     *
     * @param  array<string, mixed>  $response
     */
    public function validate(string $ceremonyId, array $response): void
    {
        if (trim($ceremonyId) === ''
            || $ceremonyId !== trim($ceremonyId)
            || mb_strlen($ceremonyId) > 191
            || preg_match('/[\x00-\x1F\x7F]/', $ceremonyId) === 1) {
            throw new AuthException('passkey_input_invalid', 'The passkey ceremony input is invalid.', 422);
        }

        try {
            $encoded = json_encode($response, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new AuthException(
                'passkey_input_invalid',
                'The passkey ceremony input is invalid.',
                422,
                previous: $exception,
            );
        }

        if (strlen($encoded) > 131_072) {
            throw new AuthException('passkey_input_invalid', 'The passkey ceremony input is invalid.', 422);
        }
    }

    /**
     * Validate one optional authenticator display name.
     */
    public function validateName(?string $name): void
    {
        if ($name !== null && (trim($name) === '' || mb_strlen($name) > 120)) {
            throw new AuthException('passkey_input_invalid', 'The passkey name is invalid.', 422);
        }
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Nvl\Auth\Contracts\PasskeyCeremony;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Auth\ValueObjects\PasskeyAssertion;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\PasskeyRegistration;
use Nvl\Auth\ValueObjects\SubjectReference;
use RuntimeException;

/**
 * Provides deterministic, non-cryptographic passkey ceremony results for tests.
 */
final class TestPasskeyCeremony implements PasskeyCeremony
{
    public ?PasskeyCredential $verifiedCredential = null;

    /**
     * Create the controllable ceremony fixture.
     */
    public function __construct(private readonly bool $failBegin = false) {}

    /** {@inheritDoc} */
    public function beginRegistration(
        Authenticatable $subject,
        SubjectReference $reference,
        array $excludedCredentialIds,
    ): PasskeyCeremonyOptions {
        return $this->options('registration');
    }

    /** {@inheritDoc} */
    public function finishRegistration(SubjectReference $subject, array $state, array $response): PasskeyRegistration
    {
        $this->requireValidResponse($response);

        return new PasskeyRegistration(
            credentialId: 'test-credential',
            publicKey: 'test-public-key',
            userHandle: 'test-user-handle',
            signatureCounter: 1,
            transports: ['internal'],
            backupEligible: true,
        );
    }

    /** {@inheritDoc} */
    public function beginAuthentication(
        ?SubjectReference $subject,
        array $allowedCredentialIds,
    ): PasskeyCeremonyOptions {
        return $this->options('authentication');
    }

    /** {@inheritDoc} */
    public function credentialId(array $response): string
    {
        $credentialId = $response['credential_id'] ?? null;

        if (! is_string($credentialId) || $credentialId === '') {
            throw new AuthException('passkey_invalid', 'The passkey response is invalid.', 422);
        }

        return $credentialId;
    }

    /** {@inheritDoc} */
    public function finishAuthentication(
        array $state,
        array $response,
        PasskeyCredential $credential,
    ): PasskeyAssertion {
        $this->requireValidResponse($response);
        $this->verifiedCredential = $credential;
        $counter = $response['signature_counter'] ?? null;

        if (! is_int($counter)) {
            throw new AuthException('passkey_invalid', 'The passkey counter is invalid.', 422);
        }

        return new PasskeyAssertion(
            credentialId: $credential->credentialId,
            signatureCounter: $counter,
            backupEligible: $credential->backupEligible,
            backedUp: false,
            userVerified: ($response['user_verified'] ?? true) === true,
        );
    }

    /**
     * Build one short-lived fake browser option set.
     */
    private function options(string $purpose): PasskeyCeremonyOptions
    {
        if ($this->failBegin) {
            throw new RuntimeException('Begin provider details must remain private.');
        }

        return new PasskeyCeremonyOptions(
            ceremonyId: (string) Str::uuid7(),
            options: ['purpose' => $purpose],
            state: ['purpose' => $purpose],
            expiresAt: CarbonImmutable::now()->addMinutes(5),
        );
    }

    /**
     * Reject intentionally invalid fake browser data.
     *
     * @param  array<string, mixed>  $response
     */
    private function requireValidResponse(array $response): void
    {
        if (($response['runtime_failure'] ?? null) === true) {
            throw new RuntimeException('Provider details must not escape the adapter boundary.');
        }

        if (($response['valid'] ?? null) !== true) {
            throw new AuthException('passkey_invalid', 'The passkey response is invalid.', 422);
        }
    }
}

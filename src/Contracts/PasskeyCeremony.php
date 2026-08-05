<?php

declare(strict_types=1);

namespace Nvl\Auth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Nvl\Auth\ValueObjects\PasskeyAssertion;
use Nvl\Auth\ValueObjects\PasskeyCeremonyOptions;
use Nvl\Auth\ValueObjects\PasskeyCredential;
use Nvl\Auth\ValueObjects\PasskeyRegistration;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Adapts WebAuthn ceremonies while Auth owns credential lifecycle and storage.
 */
interface PasskeyCeremony
{
    /**
     * Begin registration for one host subject.
     *
     * @param  list<string>  $excludedCredentialIds
     */
    public function beginRegistration(
        Authenticatable $subject,
        SubjectReference $reference,
        array $excludedCredentialIds,
    ): PasskeyCeremonyOptions;

    /**
     * Verify a registration response against persisted adapter state.
     *
     * @param  array<string, mixed>  $state
     * @param  array<string, mixed>  $response
     */
    public function finishRegistration(
        SubjectReference $subject,
        array $state,
        array $response,
    ): PasskeyRegistration;

    /**
     * Begin authentication, optionally scoped to known credential identifiers.
     *
     * @param  list<string>  $allowedCredentialIds
     */
    public function beginAuthentication(
        ?SubjectReference $subject,
        array $allowedCredentialIds,
    ): PasskeyCeremonyOptions;

    /**
     * Extract the asserted credential identifier from an untrusted browser response.
     *
     * @param  array<string, mixed>  $response
     */
    public function credentialId(array $response): string;

    /**
     * Verify an authentication response against persisted adapter state.
     *
     * @param  array<string, mixed>  $state
     * @param  array<string, mixed>  $response
     */
    public function finishAuthentication(
        array $state,
        array $response,
        PasskeyCredential $credential,
    ): PasskeyAssertion;
}

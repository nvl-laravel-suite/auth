<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries verified, provider-neutral social identity claims without OAuth tokens.
 *
 * @api
 */
final readonly class ExternalIdentity
{
    /**
     * Create a verified external identity.
     *
     * @param  array<string, mixed>  $profile
     */
    public function __construct(
        public string $provider,
        public string $providerUserId,
        public ?string $email = null,
        public ?string $name = null,
        public ?string $avatar = null,
        public array $profile = [],
        public bool $emailVerified = false,
        public ?string $emailVerificationSource = null,
        public ?string $issuer = null,
    ) {
        if (preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $this->provider) !== 1
            || trim($this->providerUserId) === '') {
            throw new InvalidArgumentException('External identity provider or user identifier is invalid.');
        }

        if ($this->issuer !== null && (strlen($this->issuer) > 2048 || filter_var($this->issuer, FILTER_VALIDATE_URL) === false || parse_url($this->issuer, PHP_URL_SCHEME) !== 'https' || parse_url($this->issuer, PHP_URL_USER) !== null || parse_url($this->issuer, PHP_URL_PASS) !== null || parse_url($this->issuer, PHP_URL_QUERY) !== null || parse_url($this->issuer, PHP_URL_FRAGMENT) !== null)) {
            throw new InvalidArgumentException('External identity issuer must be a bounded HTTPS URL.');
        }

        $encodedProfile = json_encode([
            'provider' => $this->provider,
            'provider_user_id' => $this->providerUserId,
            'email' => $this->email,
            'name' => $this->name,
            'avatar' => $this->avatar,
            'profile' => $this->profile,
            'email_verified' => $this->emailVerified,
            'email_verification_source' => $this->emailVerificationSource,
            'issuer' => $this->issuer,
        ], depth: 16);

        if (! is_string($encodedProfile) || strlen($encodedProfile) > 16_384) {
            throw new InvalidArgumentException('External identity claims must be JSON-serializable and no larger than 16 KiB.');
        }

        if ($this->emailVerified
            && ($this->email === null
                || $this->emailVerificationSource === null
                || trim($this->emailVerificationSource) === ''
                || mb_strlen($this->emailVerificationSource) > 120)) {
            throw new InvalidArgumentException(
                'Verified external emails require an address and bounded verification provenance.',
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries verified, provider-neutral social identity claims without OAuth tokens.
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
    ) {
        if (preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $this->provider) !== 1
            || trim($this->providerUserId) === '') {
            throw new InvalidArgumentException('External identity provider or user identifier is invalid.');
        }

        $encodedProfile = json_encode($this->profile);

        if (! is_string($encodedProfile) || strlen($encodedProfile) > 16_384) {
            throw new InvalidArgumentException('External identity profiles must be JSON-serializable and no larger than 16 KiB.');
        }
    }
}

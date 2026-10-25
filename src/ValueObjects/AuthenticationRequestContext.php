<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Carries optional transport context into authentication use cases.
 *
 * @api
 */
final readonly class AuthenticationRequestContext
{
    /**
     * Create bounded authentication request context.
     */
    public function __construct(
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
        public ?string $requestId = null,
        public ?string $ownerIntentNonce = null,
        public ?string $ownerSessionBinding = null,
        public ?OwnerReference $requestedOwner = null,
        public ?OwnerAuthenticationPurpose $ownerPurpose = null,
        public bool $ownerIntentSubjectBound = false,
        public ?string $ownerProvider = null,
    ) {
        if ($ownerProvider !== null && preg_match('/\A[a-z0-9][a-z0-9_.-]{0,79}\z/', $ownerProvider) !== 1) {
            throw new \InvalidArgumentException('Owner authentication provider is invalid.');
        }
        if ($ipAddress !== null && filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException('Authentication IP address is invalid.');
        }
        foreach ([[$userAgent, 1024], [$requestId, 128], [$ownerIntentNonce, 255], [$ownerSessionBinding, 255]] as [$value, $maximum]) {
            if (strlen((string) $value) > $maximum || str_contains((string) $value, "\0")) {
                throw new \InvalidArgumentException('Authentication metadata is invalid.');
            }
        }
    }
}

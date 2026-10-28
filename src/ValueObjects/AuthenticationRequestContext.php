<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Illuminate\Support\Str;
use Nvl\Auth\Enums\AuthenticationDestination;
use Nvl\Auth\Enums\OwnerAuthenticationPurpose;
use Nvl\Auth\Exceptions\AuthException;
use Nvl\Support\Ownership\ValueObjects\OwnerReference;

/**
 * Carries optional transport context into authentication use cases.
 *
 * @api
 */
final readonly class AuthenticationRequestContext implements \JsonSerializable
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
        public ?string $guardName = null,
        public ?string $sessionBinding = null,
        public ?string $tokenNamespace = null,
        public ?string $flowNonce = null,
        public ?string $browserSessionId = null,
        #[\SensitiveParameter] public ?string $browserBinding = null,
    ) {
        if (($browserSessionId === null) !== ($browserBinding === null) || $browserSessionId !== null && ! Str::isUuid($browserSessionId) || $browserBinding !== null && preg_match('/\A[0-9a-f]{64}\z/', $browserBinding) !== 1) {
            throw new \InvalidArgumentException('Invalid native browser context.');
        }
        if ($ownerProvider !== null && preg_match('/\A[a-z0-9][a-z0-9_.-]{0,79}\z/', $ownerProvider) !== 1) {
            throw new \InvalidArgumentException('Owner authentication provider is invalid.');
        }
        if ($ipAddress !== null && filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
            throw new \InvalidArgumentException('Authentication IP address is invalid.');
        }
        foreach ([[$guardName, 128], [$sessionBinding, 255], [$tokenNamespace, 128], [$flowNonce, 255], [$userAgent, 1024], [$requestId, 128], [$ownerIntentNonce, 255], [$ownerSessionBinding, 255]] as [$value, $maximum]) {
            if (strlen((string) $value) > $maximum || str_contains((string) $value, "\0")) {
                throw new \InvalidArgumentException('Authentication metadata is invalid.');
            }
        }
    }

    /** Require a destination-specific trusted binding before native issuance. */
    public function assertBound(AuthenticationDestination $destination): void
    {
        $valid = $destination === AuthenticationDestination::ApiToken
            ? $this->tokenNamespace !== null && $this->tokenNamespace !== '' && $this->flowNonce !== null && strlen($this->flowNonce) >= 32 && $this->guardName === null && $this->sessionBinding === null
            : $this->guardName !== null && $this->guardName !== '' && $this->sessionBinding !== null && $this->sessionBinding !== '' && $this->tokenNamespace === null && $this->flowNonce === null;
        if (! $valid) {
            throw new AuthException('authentication_binding_invalid', 'A trusted authentication binding is required.', 422);
        }
    }

    /** @return array<string, mixed> */
    public function facts(): array
    {
        return ['ipAddress' => $this->ipAddress, 'userAgent' => $this->userAgent, 'requestId' => $this->requestId,
            'ownerIntentNonce' => $this->ownerIntentNonce, 'ownerSessionBinding' => $this->ownerSessionBinding,
            'requestedOwner' => $this->requestedOwner?->toArray(), 'ownerPurpose' => $this->ownerPurpose?->value,
            'ownerIntentSubjectBound' => $this->ownerIntentSubjectBound, 'ownerProvider' => $this->ownerProvider,
            'guardName' => $this->guardName, 'sessionBinding' => $this->sessionBinding, 'tokenNamespace' => $this->tokenNamespace, 'flowNonce' => $this->flowNonce, 'browserSessionId' => $this->browserSessionId, 'browserBinding' => $this->browserBinding];
    }

    /** Restore bounded host/native context; this is not authentication evidence.
     * @param  array<array-key, mixed>  $facts
     */
    public static function fromFacts(array $facts): self
    {
        $named = [];
        foreach ($facts as $key => $value) {
            if (! is_string($key)) {
                throw new \InvalidArgumentException('Authentication context keys must be named.');
            }
            $named[$key] = $value;
        }
        $facts = $named;
        $keys = ['ipAddress', 'userAgent', 'requestId', 'ownerIntentNonce', 'ownerSessionBinding', 'requestedOwner', 'ownerPurpose', 'ownerIntentSubjectBound', 'ownerProvider', 'guardName', 'sessionBinding', 'tokenNamespace', 'flowNonce', 'browserSessionId', 'browserBinding'];
        if (array_diff(array_keys($facts), $keys) !== []) {
            throw new \InvalidArgumentException('Unknown authentication context.');
        }
        $owner = $facts['requestedOwner'] ?? null;
        if (is_array($owner)) {
            $owner = OwnerReference::fromArray($owner);
        }
        $purpose = $facts['ownerPurpose'] ?? null;
        if (is_string($purpose)) {
            $purpose = OwnerAuthenticationPurpose::from($purpose);
        }
        $bound = $facts['ownerIntentSubjectBound'] ?? false;
        if ($owner !== null && ! $owner instanceof OwnerReference || $purpose !== null && ! $purpose instanceof OwnerAuthenticationPurpose || ! is_bool($bound)) {
            throw new \InvalidArgumentException('Invalid authentication owner context.');
        }

        return new self(ipAddress: self::optionalString($facts, 'ipAddress'), userAgent: self::optionalString($facts, 'userAgent'), requestId: self::optionalString($facts, 'requestId'),
            ownerIntentNonce: self::optionalString($facts, 'ownerIntentNonce'), ownerSessionBinding: self::optionalString($facts, 'ownerSessionBinding'), requestedOwner: $owner,
            ownerPurpose: $purpose, ownerIntentSubjectBound: $bound, ownerProvider: self::optionalString($facts, 'ownerProvider'), guardName: self::optionalString($facts, 'guardName'),
            sessionBinding: self::optionalString($facts, 'sessionBinding'), tokenNamespace: self::optionalString($facts, 'tokenNamespace'), flowNonce: self::optionalString($facts, 'flowNonce'), browserSessionId: self::optionalString($facts, 'browserSessionId'), browserBinding: self::optionalString($facts, 'browserBinding'));
    }

    /** @return array<string, mixed> */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /** Secret-bearing native bindings are deliberately absent from generic JSON.
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return ['guardName' => $this->guardName, 'browserSessionId' => $this->browserSessionId, 'binding' => '[REDACTED]', 'requestId' => $this->requestId];
    }

    /** @param array<string, mixed> $facts */
    private static function optionalString(array $facts, string $key): ?string
    {
        $value = $facts[$key] ?? null;
        if ($value !== null && ! is_string($value)) {
            throw new \InvalidArgumentException('Invalid authentication context value.');
        }

        return $value;
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use InvalidArgumentException;

/**
 * Carries normalized first-party Auth client configuration.
 */
final readonly class AuthClientData
{
    /**
     * Create client configuration.
     *
     * @param  list<string>  $returnPaths
     * @param  list<string>  $allowedOrigins
     * @param  list<string>  $allowedFlows
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $name,
        public string $surface,
        public string $baseUrl,
        public array $returnPaths = [],
        public array $allowedOrigins = [],
        public array $allowedFlows = ['login'],
        public array $metadata = [],
        public bool $active = true,
    ) {
        if (trim($this->name) === '' || mb_strlen($this->name) > 120) {
            throw new InvalidArgumentException('Auth client names must contain between one and 120 characters.');
        }

        if (preg_match('/\A[a-z][a-z0-9_-]{0,39}\z/', $this->surface) !== 1) {
            throw new InvalidArgumentException('Auth client surfaces must be lowercase identifiers.');
        }

        if (! self::validHttpUrl($this->baseUrl, false)) {
            throw new InvalidArgumentException('Auth client base URLs must be absolute HTTP(S) URLs without credentials, query, or fragment.');
        }

        foreach ($this->returnPaths as $path) {
            if (! self::validReturnPath($path)) {
                throw new InvalidArgumentException('Auth client return paths must be absolute local paths.');
            }
        }

        foreach ($this->allowedOrigins as $origin) {
            if (! self::validOrigin($origin)) {
                throw new InvalidArgumentException('Auth client origins must be HTTP(S) origins without path, credentials, query, or fragment.');
            }
        }

        foreach ($this->allowedFlows as $flow) {
            if (! self::validFlow($flow)) {
                throw new InvalidArgumentException('Auth client flows must be lowercase identifiers.');
            }
        }

        $encodedMetadata = json_encode($this->metadata);

        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16_384) {
            throw new InvalidArgumentException('Auth client metadata must be JSON-serializable and no larger than 16 KiB.');
        }
    }

    /**
     * Determine whether a URL is safe for client redirect configuration.
     */
    private static function validHttpUrl(string $url, bool $originOnly): bool
    {
        if (mb_strlen($url) > 2_048 || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $parts = parse_url($url);

        if (! is_array($parts)
            || ! isset($parts['scheme'], $parts['host'])
            || ! in_array(mb_strtolower((string) $parts['scheme']), ['http', 'https'], true)
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            return false;
        }

        return ! $originOnly || ! isset($parts['path']) || $parts['path'] === '' || $parts['path'] === '/';
    }

    /**
     * Determine whether an untrusted return-path value is safe.
     */
    private static function validReturnPath(mixed $path): bool
    {
        return is_string($path)
            && mb_strlen($path) <= 2_048
            && str_starts_with($path, '/')
            && ! str_starts_with($path, '//')
            && preg_match('/[\x00-\x1F\x7F\\\\]/', $path) !== 1;
    }

    /**
     * Determine whether an untrusted origin value is safe.
     */
    private static function validOrigin(mixed $origin): bool
    {
        return is_string($origin) && self::validHttpUrl($origin, true);
    }

    /**
     * Determine whether an untrusted flow value is canonical.
     */
    private static function validFlow(mixed $flow): bool
    {
        return is_string($flow) && preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $flow) === 1;
    }
}

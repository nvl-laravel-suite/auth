<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use InvalidArgumentException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class UpdateClientData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $returnPaths
     * @param  list<string>  $allowedOrigins
     * @param  list<string>  $allowedFlows
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $name,
        public readonly string $surface,
        public readonly string $baseUrl,
        public readonly array $returnPaths = [],
        public readonly array $allowedOrigins = [],
        public readonly array $allowedFlows = ['login'],
        public readonly array $metadata = [],
        public readonly bool $active = true,
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

    private static function validReturnPath(mixed $path): bool
    {
        return is_string($path)
            && mb_strlen($path) <= 2_048
            && str_starts_with($path, '/')
            && ! str_starts_with($path, '//')
            && preg_match('/[\x00-\x1F\x7F\\\\]/', $path) !== 1;
    }

    private static function validOrigin(mixed $origin): bool
    {
        return is_string($origin) && self::validHttpUrl($origin, true);
    }

    private static function validFlow(mixed $flow): bool
    {
        return is_string($flow) && preg_match('/\A[a-z][a-z0-9_.-]{0,79}\z/', $flow) === 1;
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:120'],
            'surface' => ['required', 'string', 'max:40'],
            'baseUrl' => ['required', 'url', 'max:2048'],
            'returnPaths' => ['sometimes', 'array'],
            'returnPaths.*' => ['string', 'max:2048'],
            'allowedOrigins' => ['sometimes', 'array'],
            'allowedOrigins.*' => ['url', 'max:2048'],
            'allowedFlows' => ['sometimes', 'array'],
            'allowedFlows.*' => ['string', 'max:80'],
            'metadata' => ['sometimes', 'array'],
            'active' => ['sometimes', 'boolean'],
        ];
    }
}

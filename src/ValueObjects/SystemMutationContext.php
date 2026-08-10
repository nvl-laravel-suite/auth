<?php

declare(strict_types=1);

namespace Nvl\Auth\ValueObjects;

use Illuminate\Contracts\Auth\Authenticatable;
use InvalidArgumentException;
use JsonException;

/**
 * Describes one explicitly authorized actorless package mutation.
 */
final readonly class SystemMutationContext
{
    /**
     * Create a traceable system mutation context.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public string $reason,
        public string $correlationId,
        public ?Authenticatable $actor = null,
        public array $metadata = [],
    ) {
        if (trim($this->reason) === '' || mb_strlen($this->reason) > 500) {
            throw new InvalidArgumentException('System mutation reasons must contain between one and 500 characters.');
        }

        if (trim($this->correlationId) === '' || mb_strlen($this->correlationId) > 160) {
            throw new InvalidArgumentException('System mutation correlation identifiers must contain between one and 160 characters.');
        }

        try {
            $encoded = json_encode($this->metadata, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new InvalidArgumentException('System mutation metadata must be JSON serializable.', previous: $exception);
        }

        if (strlen($encoded) > 65_535) {
            throw new InvalidArgumentException('System mutation metadata must not exceed 65,535 encoded bytes.');
        }
    }

    /**
     * Return bounded audit and event metadata for this mutation.
     *
     * @return array{system: array{reason: string, correlation_id: string, metadata: array<string, mixed>}}
     */
    public function auditMetadata(): array
    {
        return [
            'system' => [
                'reason' => trim($this->reason),
                'correlation_id' => trim($this->correlationId),
                'metadata' => $this->metadata,
            ],
        ];
    }
}

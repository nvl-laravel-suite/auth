<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Minimal subject identity for delivery listeners and consumer responses.
 *
 * @api
 */
final class AuthSubjectReferenceData implements Arrayable, JsonSerializable
{
    /**
     * Create a subject delivery reference.
     */
    public function __construct(
        public readonly string $type,
        public readonly string $id,
    ) {}

    /**
     * Project the package's canonical subject reference.
     */
    public static function fromReference(SubjectReference $reference): self
    {
        return new self(
            type: $reference->type,
            id: $reference->identifier,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'id' => $this->id,
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}

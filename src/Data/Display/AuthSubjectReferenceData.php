<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Minimal subject identity for delivery listeners and generated client types.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class AuthSubjectReferenceData extends Data
{
    use DataTransform;

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
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/** Exact membership revision required for revocation. */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class MembershipRevisionData extends Data
{
    use DataTransform;

    public function __construct(public readonly int $expectedRevision) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return ['expected_revision' => ['required', 'integer', 'min:1']];
    }
}

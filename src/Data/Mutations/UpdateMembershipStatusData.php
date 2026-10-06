<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Illuminate\Validation\Rule;
use InvalidArgumentException;
use Nvl\Auth\Enums\MembershipStatus;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Describes one optimistic membership status mutation.
 *
 * @api
 */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class UpdateMembershipStatusData extends Data
{
    use DataTransform;

    public function __construct(public readonly MembershipStatus $status, public readonly int $expectedRevision)
    {
        if ($this->expectedRevision < 1) {
            throw new InvalidArgumentException('Membership revision must be positive.');
        }
    }

    /** @return array<string, mixed> */
    public static function rules(): array
    {
        return [
            'status' => ['required', Rule::enum(MembershipStatus::class)],
            'expected_revision' => ['required', 'integer', 'min:1'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use InvalidArgumentException;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Selects the recipient and revision for an ownership transfer. */
final class TransferMembershipOwnershipData extends Data
{
    use DataTransform;

    public function __construct(public readonly string $recipientMembershipId, public readonly int $expectedRevision)
    {
        if (! preg_match('/^[0-9a-f-]{36}$/i', $this->recipientMembershipId) || $this->expectedRevision < 1) {
            throw new InvalidArgumentException('Ownership transfer input is invalid.');
        }
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient_membership_id' => ['required', 'uuid'],
            'expected_revision' => ['required', 'integer', 'min:1'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use InvalidArgumentException;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/**
 * Selects the recipient and revision for an ownership transfer.
 *
 * @api
 */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class TransferMembershipOwnershipData extends Data
{
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

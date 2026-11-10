<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Illuminate\Validation\Rule;
use InvalidArgumentException;
use Nvl\Auth\Enums\MembershipStatus;

/**
 * Describes one optimistic membership status mutation.
 *
 * @api
 */
final class UpdateMembershipStatusData
{
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

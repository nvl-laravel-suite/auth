<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Display;

use Carbon\CarbonImmutable;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Bounded invitation context for host-owned delivery listeners.
 *
 * @api
 */
#[MapOutputName(CamelCaseMapper::class)]
final class InvitationDeliveryData extends Data
{
    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, bool|float|int|string|null>  $metadata
     */
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $purpose,
        public readonly string $recipient,
        public readonly ?AuthSubjectReferenceData $inviter,
        public readonly array $roles,
        public readonly array $permissions,
        public readonly array $metadata,
        public readonly CarbonImmutable $expiresAt,
        public readonly int $resendCount,
    ) {}
}

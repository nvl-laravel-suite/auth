<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Display;

use Carbon\CarbonImmutable;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Bounded invitation context for host-owned delivery listeners.
 */
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class InvitationDeliveryData extends Data
{
    use DataTransform;

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

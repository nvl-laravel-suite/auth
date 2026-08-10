<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Queries;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
/** Validated invitation management filters over queryable package fields. */
final class InvitationIndexQueryData extends Data
{
    use DataTransform;

    /** Create the bounded invitation query. */
    public function __construct(
        public readonly ?string $recipient = null,
        public readonly ?string $type = null,
        public readonly ?string $purpose = null,
        public readonly ?string $lifecycle = null,
        public readonly ?string $expiresAfter = null,
        public readonly ?string $expiresBefore = null,
        public readonly ?string $context = null,
        public readonly ?int $perPage = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['sometimes', 'email:rfc', 'max:320'],
            'type' => ['sometimes', 'string', 'max:80'],
            'purpose' => ['sometimes', 'string', 'max:120'],
            'lifecycle' => ['sometimes', 'in:active,accepted,revoked,expired'],
            'expiresAfter' => ['sometimes', 'date'],
            'expiresBefore' => ['sometimes', 'date', 'after:expiresAfter'],
            'context' => ['sometimes', 'string', 'max:191'],
            'perPage' => ['sometimes', 'integer', 'between:1,100'],
        ];
    }
}

<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Queries;

use InvalidArgumentException;
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

    /** @var list<string>|null */
    public readonly ?array $types;

    /**
     * Create the bounded invitation query.
     *
     * @param  list<string>|null  $types
     */
    public function __construct(
        public readonly ?string $recipient = null,
        public readonly ?string $type = null,
        public readonly ?string $purpose = null,
        public readonly ?string $lifecycle = null,
        public readonly ?string $expiresAfter = null,
        public readonly ?string $expiresBefore = null,
        public readonly ?string $context = null,
        public readonly ?int $perPage = null,
        ?array $types = null,
    ) {
        $this->types = self::normalizeTypes($types);
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['sometimes', 'email:rfc', 'max:320'],
            'type' => ['sometimes', 'string', 'max:80'],
            'types' => ['sometimes', 'array', 'max:20'],
            'types.*' => ['string', 'distinct', 'max:80'],
            'purpose' => ['sometimes', 'string', 'max:120'],
            'lifecycle' => ['sometimes', 'in:active,accepted,revoked,expired'],
            'expiresAfter' => ['sometimes', 'date'],
            'expiresBefore' => ['sometimes', 'date', 'after:expiresAfter'],
            'context' => ['sometimes', 'string', 'max:191'],
            'perPage' => ['sometimes', 'integer', 'between:1,100'],
        ];
    }

    /**
     * Normalize an optional list of invitation types.
     *
     * @param  array<array-key, mixed>|null  $types
     * @return list<string>|null
     */
    private static function normalizeTypes(?array $types): ?array
    {
        if ($types === null || $types === []) {
            return null;
        }

        if (count($types) > 20 || ! array_is_list($types)) {
            throw new InvalidArgumentException('Invitation types must be a list containing at most 20 values.');
        }

        $normalized = [];

        foreach ($types as $type) {
            if (! is_string($type)
                || trim($type) === ''
                || mb_strlen($type) > 80) {
                throw new InvalidArgumentException('Invitation types must contain between one and 80 characters.');
            }

            $normalized[trim($type)] = true;
        }

        return array_keys($normalized);
    }
}

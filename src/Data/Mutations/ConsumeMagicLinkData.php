<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/**
 * Recipient and secret input for consuming a magic-link challenge.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class ConsumeMagicLinkData extends Data
{
    use DataTransform;

    public function __construct(
        public readonly ?string $recipient,
        public readonly string $token,
        public readonly ?string $challengeId = null,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:255'],
            'recipient' => ['required_without:challengeId', 'email:rfc', 'max:320'],
            'challengeId' => ['required_without:recipient', 'uuid'],
        ];
    }
}

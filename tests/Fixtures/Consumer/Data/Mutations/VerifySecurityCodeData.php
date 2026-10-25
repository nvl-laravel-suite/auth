<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Recipient, purpose, and code input for security-code verification.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class VerifySecurityCodeData extends Data
{
    public function __construct(
        public readonly string $recipient,
        public readonly string $purpose,
        public readonly string $code,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['required', 'string', 'max:255'],
            'purpose' => ['required', 'string', 'max:255'],
            'code' => ['required', 'string', 'max:128'],
        ];
    }
}

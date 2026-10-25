<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use SensitiveParameter;
use Spatie\LaravelData\Attributes\Hidden;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Sensitive password input for confirming the authenticated subject.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class ConfirmPasswordData extends Data
{
    public function __construct(
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $password,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'password' => ['required', 'string', 'max:4096'],
        ];
    }
}

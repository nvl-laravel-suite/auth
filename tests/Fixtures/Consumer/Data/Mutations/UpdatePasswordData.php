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
 * Current and replacement sensitive passwords for a password change.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class UpdatePasswordData extends Data
{
    public function __construct(
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $currentPassword,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $password,
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $passwordConfirmation,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'currentPassword' => ['required', 'string', 'max:4096'],
            'password' => ['required', 'string', 'min:8', 'max:4096', 'confirmed'],
        ];
    }
}

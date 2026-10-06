<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Data\Traits\DataTransform;
use SensitiveParameter;
use Spatie\LaravelData\Attributes\Hidden;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;

/**
 * Validated self-service account deletion confirmation.
 *
 * @api
 */
#[MapInputName(CamelCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
final class DeleteOwnAccountData extends Data
{
    use DataTransform;

    /** Create the deletion mutation. */
    public function __construct(
        #[Hidden]
        #[SensitiveParameter]
        public readonly string $currentPassword,
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return ['currentPassword' => ['required', 'string', 'max:4096']];
    }
}

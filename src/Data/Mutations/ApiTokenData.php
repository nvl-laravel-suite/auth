<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Carbon\CarbonImmutable;
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
final class ApiTokenData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $abilities
     */
    public function __construct(
        public readonly string $name,
        public readonly array $abilities,
        public readonly ?CarbonImmutable $expiresAt = null,
    ) {
        if (trim($this->name) === '' || $this->name !== trim($this->name) || mb_strlen($this->name) > 120) {
            throw new InvalidArgumentException('API token name must contain between one and 120 characters.');
        }

        if ($this->abilities === []) {
            throw new InvalidArgumentException('API tokens require at least one ability.');
        }
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:120'],
            'abilities' => ['required', 'array', 'min:1', 'max:100'],
            'abilities.*' => ['required', 'string', 'max:120', 'distinct:strict'],
            'expiresAt' => ['sometimes', 'nullable', 'date', 'after:now'],
        ];
    }
}

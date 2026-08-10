<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

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
final class StoreInvitationData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public readonly string $recipient,
        public readonly string $type = 'registration',
        public readonly string $purpose = 'registration',
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $metadata = [],
        public ?string $locale = null,
        public readonly ?string $context = null,
    ) {
        if (trim($this->recipient) === '' || mb_strlen($this->recipient) > 320) {
            throw new InvalidArgumentException('Invitation recipients must contain between one and 320 characters.');
        }

        if (trim($this->type) === '' || mb_strlen($this->type) > 80
            || trim($this->purpose) === '' || mb_strlen($this->purpose) > 120) {
            throw new InvalidArgumentException('Invitation type or purpose is invalid.');
        }

        if ($this->context !== null && (trim($this->context) === '' || mb_strlen($this->context) > 191)) {
            throw new InvalidArgumentException('Invitation contexts must contain between one and 191 characters.');
        }

        foreach ([...$this->roles, ...$this->permissions] as $grant) {
            if (! self::validGrant($grant)) {
                throw new InvalidArgumentException('Invitation role and permission names must be non-empty strings no longer than 255 characters.');
            }
        }

        $encodedMetadata = json_encode($this->metadata);
        if (! is_string($encodedMetadata) || strlen($encodedMetadata) > 16_384) {
            throw new InvalidArgumentException('Invitation metadata must be JSON-serializable and no larger than 16 KiB.');
        }
    }

    private static function validGrant(mixed $grant): bool
    {
        return is_string($grant) && trim($grant) !== '' && mb_strlen($grant) <= 255;
    }

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'recipient' => ['required', 'string', 'max:320'],
            'type' => ['sometimes', 'string', 'max:80'],
            'purpose' => ['sometimes', 'string', 'max:120'],
            'roles' => ['sometimes', 'array'],
            'roles.*' => ['string', 'max:255'],
            'permissions' => ['sometimes', 'array'],
            'permissions.*' => ['string', 'max:255'],
            'metadata' => ['sometimes', 'array'],
            'context' => ['sometimes', 'nullable', 'string', 'max:191'],
        ];
    }
}

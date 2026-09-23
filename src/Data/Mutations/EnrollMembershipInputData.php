<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Attributes\MapInputName;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\CamelCaseMapper;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

/** Validated host principal and permissions for membership enrollment. */
#[MapInputName(SnakeCaseMapper::class)]
#[MapOutputName(CamelCaseMapper::class)]
#[TypeScript]
final class EnrollMembershipInputData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        public readonly string $subjectType,
        public readonly string $subjectId,
        public readonly array $roles = [],
        public readonly array $permissions = [],
    ) {}

    /** @return array<string, list<string>> */
    public static function rules(): array
    {
        return [
            'subject_type' => ['required', 'string', 'max:160'],
            'subject_id' => ['required', 'string', 'max:191'],
            'roles' => ['sometimes', 'array', 'max:100'],
            'roles.*' => ['string', 'max:160', 'distinct'],
            'permissions' => ['sometimes', 'array', 'max:100'],
            'permissions.*' => ['string', 'max:160', 'distinct'],
        ];
    }

    /** Build the existing transport-neutral enrollment contract. */
    public function enrollment(): EnrollMembershipData
    {
        return new EnrollMembershipData(
            new SubjectReference($this->subjectType, $this->subjectId),
            $this->roles,
            $this->permissions,
        );
    }
}

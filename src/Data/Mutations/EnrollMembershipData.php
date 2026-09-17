<?php

declare(strict_types=1);

namespace Nvl\Auth\Data\Mutations;

use InvalidArgumentException;
use Nvl\Auth\ValueObjects\SubjectReference;
use Nvl\Data\Traits\DataTransform;
use Spatie\LaravelData\Data;
use Spatie\TypeScriptTransformer\Attributes\LiteralTypeScriptType;
use Spatie\TypeScriptTransformer\Attributes\TypeScript;

#[TypeScript]
/** Describes one tenant membership enrollment. */
final class EnrollMembershipData extends Data
{
    use DataTransform;

    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        #[LiteralTypeScriptType('{ type: string; identifier: string }')]
        public readonly SubjectReference $subject,
        public readonly array $roles = [],
        public readonly array $permissions = [],
    ) {
        foreach ([$this->roles, $this->permissions] as $identifiers) {
            if (count($identifiers) > 500 || count(array_unique($identifiers)) !== count($identifiers)) {
                throw new InvalidArgumentException('Membership access identifiers must be distinct and bounded.');
            }
            foreach ($identifiers as $identifier) {
                if (! is_string($identifier) || trim($identifier) === '' || mb_strlen($identifier) > 160) {
                    throw new InvalidArgumentException('Membership access identifiers are invalid.');
                }
            }
        }
    }
}

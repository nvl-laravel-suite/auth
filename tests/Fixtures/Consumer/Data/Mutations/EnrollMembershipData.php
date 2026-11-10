<?php

declare(strict_types=1);

namespace Nvl\Auth\Tests\Fixtures\Consumer\Data\Mutations;

use InvalidArgumentException;
use Nvl\Auth\ValueObjects\SubjectReference;

/**
 * Describes one tenant membership enrollment.
 *
 * @api
 */
final class EnrollMembershipData
{
    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        public readonly SubjectReference $subject,
        public readonly array $roles = [],
        public readonly array $permissions = [],
    ) {
        foreach ([$this->roles, $this->permissions] as $identifiers) {
            if (count($identifiers) > 500 || count(array_unique($identifiers)) !== count($identifiers)) {
                throw new InvalidArgumentException('Membership access identifiers must be distinct and bounded.');
            }
            foreach ($identifiers as $identifier) {
                if (trim($identifier) === '' || mb_strlen($identifier) > 160) {
                    throw new InvalidArgumentException('Membership access identifiers are invalid.');
                }
            }
        }
    }
}
